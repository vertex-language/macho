package link

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/image"
)

// __compact_unwind consumption and __TEXT,__unwind_info synthesis.
//
// The compiler emits one fixed-size record per function into
// __LD,__compact_unwind: a relocated pointer to the function, its length, a
// packed encoding of its prologue, and relocated pointers to a personality
// routine and an LSDA. The linker's job is to throw that array away and
// replace it with a two-level page table sorted by address, which is what the
// runtime binary-searches on a throw.
//
// # Regular pages only
//
// A compressed second-level page holds up to 1021 entries against a regular
// page's 511, but only when few enough distinct encodings appear, and its
// entries carry a 24-bit function offset relative to the page's first entry.
// Both of those depend on which functions landed where — which is not known
// when the section has to be sized.
//
// A regular page is 8 bytes of header and 511 eight-byte entries, and its size
// is a function of the entry count alone. That makes __unwind_info sizeable
// before layout and generatable after it, which is what lets it be an ordinary
// synthetic instead of a fourth term in the layout fixpoint. The cost is
// roughly twice the bytes of what ld64 emits, in a section that is a low
// single-digit percentage of a binary. Compressed pages are the optimization
// and they need unwind to move inside the fixpoint first.
//
// # Known gap
//
// An entry whose encoding is zero means "no compact representation; use the
// FDE in __eh_frame". Those are emitted here as an encoding of zero, which is
// correct only because __eh_frame is passed through unchanged — see the
// README. When __eh_frame stops being passed through, this has to synthesize
// UNWIND_..._MODE_DWARF entries pointing at the surviving FDEs.

// ---------------------------------------------------------------------------
// Constants that belong in macho/unwind.go. Delete this block if the names
// there match; it is here because these encoders were written against it.
// ---------------------------------------------------------------------------

const (
	unwindSectionVersion = 1

	unwindSecondLevelRegular = 2

	// unwindPersonalityMask holds a 1-based index into the personality array,
	// which is why there can be at most three personalities in an image.
	unwindPersonalityMask = 0x30000000

	unwindPersonalityShift = 28
	maxPersonalities       = 3

	// secondLevelPageBytes is fixed, which is what makes an index entry's
	// page offset a multiplication rather than a running sum.
	secondLevelPageBytes = 4096

	unwindHeaderSize     = 28 // seven uint32
	unwindIndexEntrySize = 12
	unwindLSDAEntrySize  = 8
	regularPageHeader    = 8
	regularEntrySize     = 8
)

// regularEntriesPerPage is how many entries fit a regular second-level page.
const regularEntriesPerPage = (secondLevelPageBytes - regularPageHeader) / regularEntrySize // 511

// cuEntry is one decoded __compact_unwind record, with its relocations already
// resolved to the things they name.
type cuEntry struct {
	fn     *image.Atom // the function this describes
	fnOff  uint64      // offset within fn; nonzero for a second entry on one atom
	length uint32
	enc    uint32

	// personality is the routine the entry names, or nil. It is referenced
	// through the GOT, not directly: the personality array holds offsets to
	// pointers, so the routine can live in another image.
	personality *image.Sym

	lsda    *image.Atom
	lsdaOff uint64
}

// unwind consumes every __compact_unwind section and registers the synthetic
// that replaces them.
func (l *Linker) unwind(img *image.Image) error {
	for _, a := range l.atoms {
		if !l.isCompactUnwind(a) || !a.Live || a.Coalesced {
			continue
		}
		e, ok, err := l.decodeCompactUnwind(a)
		if err != nil {
			return err
		}
		// The record is consumed whether or not it produced an entry: it must
		// not reach an output section under its input name, and __LD exists
		// only in object files.
		a.Live = false
		if ok {
			l.cu = append(l.cu, e)
		}
	}
	if len(l.cu) == 0 {
		return nil
	}

	// A personality routine is reached through a GOT slot. Reserving it here
	// rather than letting Scan discover it is deliberate: Scan never sees
	// these relocations, because the atoms carrying them are already dead by
	// the time it runs.
	seen := make(map[*image.Sym]bool)
	var personalities []*image.Sym
	for _, e := range l.cu {
		if e.personality == nil || seen[e.personality] {
			continue
		}
		seen[e.personality] = true
		personalities = append(personalities, e.personality)
		l.reqs.GOT(e.personality)
	}
	if len(personalities) > maxPersonalities {
		// The index lives in two bits of the encoding word. A fourth
		// personality cannot be named, and silently reusing an index attaches
		// the wrong cleanup handler to a throw.
		return fmt.Errorf("link: %d personality routines; the compact unwind encoding names at most %d",
			len(personalities), maxPersonalities)
	}

	return img.AddSynthetic(&unwindSynthetic{l: l, personalities: personalities})
}

// isCompactUnwind reports whether an atom came from a compact unwind section.
func (l *Linker) isCompactUnwind(a *image.Atom) bool {
	k, ok := l.atomSection[a]
	if !ok {
		return false
	}
	return k.Name.Section == macho.SECT_COMPACT_UNWIND
}

// decodeCompactUnwind reads one record.
//
// The three pointer fields are relocations, not values: the record as the
// compiler wrote it has zeros in them. So the function, the personality, and
// the LSDA are read out of the atom's relocation list by offset, and the two
// scalar fields out of its bytes.
func (l *Linker) decodeCompactUnwind(a *image.Atom) (cuEntry, bool, error) {
	data, err := a.Source.Bytes()
	if err != nil {
		return cuEntry{}, false, fmt.Errorf("link: %s: %w", atomWhere(a), err)
	}
	if len(data) < cuLSDAOffset+8 {
		return cuEntry{}, false, fmt.Errorf("link: %s is %d bytes, too short for a compact unwind record",
			atomWhere(a), len(data))
	}

	e := cuEntry{
		length: binary.LittleEndian.Uint32(data[cuLengthOffset:]),
		enc:    binary.LittleEndian.Uint32(data[cuEncodingOffset:]),
	}
	for _, r := range a.Relocs {
		switch r.Offset {
		case cuFunctionOffset:
			e.fn, e.fnOff = l.referent(r), uint64(r.Addend)
		case cuPersonalityOffset:
			e.personality = r.Sym
		case cuLSDAOffset:
			e.lsda, e.lsdaOff = l.referent(r), uint64(r.Addend)
		}
	}
	if e.fn == nil || !e.fn.Live || e.fn.Coalesced {
		// The function was dead-stripped or lost a weak election. Its unwind
		// entry goes with it; keeping one would describe a range no code
		// occupies and shadow the entry for whatever landed there instead.
		return cuEntry{}, false, nil
	}
	return e, true, nil
}

// referent is the atom a record's function or LSDA relocation names.
//
// Two spellings reach here and both are ordinary. clang names the function
// with a section-relative relocation, which split() has already bound to the
// atom covering that address. An assembler with no way to spell "the address
// of section N" names the symbol instead, and a symbol with external linkage
// arrives interned rather than bound — so the atom is the one defining it.
func (l *Linker) referent(r image.Reloc) *image.Atom {
	a := r.Atom
	if a == nil {
		a = l.definingAtom(r.Sym)
	}
	if a == nil {
		return nil
	}
	return l.survivor(a)
}

// survivor follows a folded atom to the copy that was kept.
func (l *Linker) survivor(a *image.Atom) *image.Atom {
	for {
		to, ok := l.folded[a]
		if !ok {
			return a
		}
		a = to
	}
}

// unwindSynthetic is __TEXT,__unwind_info.
type unwindSynthetic struct {
	l             *Linker
	personalities []*image.Sym

	sec *image.Section
	src *image.RawSource
}

func (u *unwindSynthetic) SyntheticName() string { return "__TEXT,__unwind_info" }

// Prepare sizes the section. Every term is a count, and every count is already
// final: which functions are live was decided by the sweep, and how many pages
// they need follows from the entry count because the pages are regular.
func (u *unwindSynthetic) Prepare(img *image.Image) error {
	n := len(u.l.cu)
	if n == 0 {
		return nil
	}
	lsdas := 0
	for _, e := range u.l.cu {
		if e.lsda != nil {
			lsdas++
		}
	}
	pages := (n + regularEntriesPerPage - 1) / regularEntriesPerPage

	size := uint64(unwindHeaderSize) +
		uint64(len(u.personalities))*4 +
		uint64(pages+1)*unwindIndexEntrySize + // the extra entry is the sentinel
		uint64(lsdas)*unwindLSDAEntrySize +
		uint64(pages)*secondLevelPageBytes

	sec, err := img.Section(image.SectionKey{
		Name: macho.Sec(macho.SEG_TEXT, macho.SECT_UNWIND_INFO),
		Type: macho.S_REGULAR,
	})
	if err != nil {
		return err
	}
	u.sec, u.src = sec, image.NewRawSource(size)
	return u.l.addSynthetic(sec, &image.Atom{
		Name: "<unwind_info>", Source: u.src, Align: 4,
	})
}

func (u *unwindSynthetic) Generate(img *image.Image) error {
	if u.sec == nil {
		return nil
	}
	base := img.BaseAddress()

	// Every offset in the section is from the Mach-O header, and the table is
	// binary-searched, so the sort is load-bearing rather than cosmetic. Ties
	// cannot happen — two entries at one address describe one function twice —
	// but the sort is stable so that if they do, the output is at least
	// reproducible.
	type resolved struct {
		fn, lsda uint64
		hasLSDA  bool
		enc      uint32
		length   uint32
	}
	entries := make([]resolved, 0, len(u.l.cu))
	for _, e := range u.l.cu {
		fn, err := e.fn.Addr()
		if err != nil {
			return err
		}
		r := resolved{fn: fn + e.fnOff - base, enc: e.enc, length: e.length}
		if p := u.personalityIndex(e.personality); p != 0 {
			r.enc = (r.enc &^ unwindPersonalityMask) | uint32(p)<<unwindPersonalityShift
		}
		if e.lsda != nil {
			l, err := e.lsda.Addr()
			if err != nil {
				return err
			}
			r.lsda, r.hasLSDA = l+e.lsdaOff-base, true
		}
		entries = append(entries, r)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].fn < entries[j].fn })

	pages := (len(entries) + regularEntriesPerPage - 1) / regularEntriesPerPage
	lsdaCount := 0
	for _, e := range entries {
		if e.hasLSDA {
			lsdaCount++
		}
	}

	personalityOff := uint32(unwindHeaderSize)
	indexOff := personalityOff + uint32(len(u.personalities))*4
	lsdaOff := indexOff + uint32(pages+1)*unwindIndexEntrySize
	pagesOff := lsdaOff + uint32(lsdaCount)*unwindLSDAEntrySize

	buf := make([]byte, u.src.Size())
	put := func(off uint32, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }

	put(0, unwindSectionVersion)
	put(4, personalityOff) // common encodings: none, since regular pages hold
	put(8, 0)              // their encodings inline
	put(12, personalityOff)
	put(16, uint32(len(u.personalities)))
	put(20, indexOff)
	put(24, uint32(pages+1))

	// A personality array entry is the offset of the GOT slot holding the
	// routine's address, not the routine's own offset — the routine is
	// usually in another image and has no offset here.
	for i, sym := range u.personalities {
		slot, err := u.l.personalitySlot(img, sym)
		if err != nil {
			return err
		}
		put(personalityOff+uint32(i)*4, uint32(slot-base))
	}

	li := lsdaOff
	for p := 0; p < pages; p++ {
		lo := p * regularEntriesPerPage
		hi := lo + regularEntriesPerPage
		if hi > len(entries) {
			hi = len(entries)
		}
		page := pagesOff + uint32(p)*secondLevelPageBytes

		ix := indexOff + uint32(p)*unwindIndexEntrySize
		put(ix, uint32(entries[lo].fn))
		put(ix+4, page)
		put(ix+8, li)

		put(page, unwindSecondLevelRegular)
		binary.LittleEndian.PutUint16(buf[page+4:], regularPageHeader)
		binary.LittleEndian.PutUint16(buf[page+6:], uint16(hi-lo))
		for i, e := range entries[lo:hi] {
			at := page + regularPageHeader + uint32(i)*regularEntrySize
			put(at, uint32(e.fn))
			put(at+4, e.enc)
			if e.hasLSDA {
				put(li, uint32(e.fn))
				put(li+4, uint32(e.lsda))
				li += unwindLSDAEntrySize
			}
		}
	}

	// The sentinel. Its function offset is one past the last function, which
	// is the only thing that says how many bytes the last real entry covers —
	// without it a lookup past the end of the last function succeeds.
	//
	// The last entry by address, not the last one the input happened to
	// list: the table above is sorted and this has to agree with it, or the
	// sentinel lands inside a function and everything past it is invisible.
	last := entries[len(entries)-1]
	sent := indexOff + uint32(pages)*unwindIndexEntrySize
	put(sent, uint32(last.fn+uint64(last.length)))
	put(sent+4, 0)
	put(sent+8, li)

	return u.src.Set(buf)
}

// personalityIndex returns the 1-based index the encoding carries, or 0 for no
// personality.
func (u *unwindSynthetic) personalityIndex(sym *image.Sym) int {
	for i, p := range u.personalities {
		if p == sym {
			return i + 1
		}
	}
	return 0
}

// personalitySlot returns the address of a personality routine's GOT entry.
func (l *Linker) personalitySlot(img *image.Image, sym *image.Sym) (uint64, error) {
	i, ok := l.reqs.GOTIndex(sym)
	if !ok {
		return 0, fmt.Errorf("link: personality %s has no GOT slot", sym.Name)
	}
	for _, sec := range img.Sections() {
		if sec.Key.Name == macho.Sec(macho.SEG_DATA_CONST, macho.SECT_GOT) {
			return sec.Addr + uint64(i)*uint64(l.be.WordSize()), nil
		}
	}
	return 0, fmt.Errorf("link: the image has no __DATA_CONST,__got for personality %s", sym.Name)
}