package link

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/image"
	"github.com/vertex-language/macho/obj"
)

// Splitting inputs into atoms.
//
// An atom is the unit of layout, dead-stripping, and ordering. Where the cuts
// fall depends on the section:
//
//   - Ordinary sections are cut at symbol boundaries, but only under
//     MH_SUBSECTIONS_VIA_SYMBOLS. Without that flag the compiler has not
//     promised the cuts are safe, and making them anyway breaks any code that
//     reaches a neighbour by adding to a symbol.
//   - Literal sections are cut by content: at NUL boundaries for __cstring,
//     at the element size for the fixed-width literal types. They usually
//     carry no symbols at all, so symbol boundaries would leave them as one
//     atom and nothing could be deduplicated.
//   - __compact_unwind is cut at its fixed entry size.
//   - __eh_frame is cut at CIE and FDE boundaries, which the entries' own
//     length prefixes give.
//
// This is also where a relocation stops being a pair of on-disk entries and
// becomes one image.Reloc: SUBTRACTOR and its UNSIGNED collapse into a single
// difference, and an ARM64_RELOC_ADDEND folds into the entry it precedes. The
// pair is one logical operation, and keeping it as two would let one half be
// applied without the other.

// splitState is the per-input bookkeeping split builds.
type splitState struct {
	// bySection holds each object section's atoms in ascending offset order,
	// which is what makes the address lookup a binary search.
	bySection map[*obj.Section][]*image.Atom

	// bySymbol maps a defining nlist entry to the atom that carries it, and
	// to where inside that atom the definition starts. The offset is zero for
	// the symbol that begins an atom; it is non-zero for an .alt_entry, and
	// for every symbol of an object that did not set
	// MH_SUBSECTIONS_VIA_SYMBOLS, where the whole section is one atom and
	// only the first symbol lands on its start.
	bySymbol map[*obj.Symbol]symPos
}

// symPos is a definition's position: the atom that holds it and the offset
// from that atom's start.
type symPos struct {
	atom *image.Atom
	off  uint64
}

// split turns every loaded object into atoms.
func (l *Linker) split(img *image.Image) error {
	for _, in := range l.inputs {
		if in.kind != inputObject {
			continue
		}
		if err := l.splitInput(img, in); err != nil {
			return fmt.Errorf("%s: %w", in.name, err)
		}
	}
	// Relocations are converted in a second pass over everything, because a
	// relocation may name an atom in an input that had not been split yet
	// when its own input was.
	for _, in := range l.inputs {
		if in.kind != inputObject || in.split == nil {
			continue
		}
		if err := l.convertRelocs(img, in); err != nil {
			return fmt.Errorf("%s: %w", in.name, err)
		}
	}
	return nil
}

func (l *Linker) splitInput(img *image.Image, in *inputFile) error {
	st := &splitState{
		bySection: make(map[*obj.Section][]*image.Atom),
		bySymbol:  make(map[*obj.Symbol]symPos),
	}
	in.split = st
	ii := l.imageInput(img, in)

	for _, sec := range in.obj.Sections {
		atoms, err := l.splitSection(in, sec)
		if err != nil {
			return fmt.Errorf("%s: %w", sec, err)
		}
		if l.atomSection == nil {
			l.atomSection = make(map[*image.Atom]image.SectionKey)
		}
		key := image.SectionKey{Name: sec.SecName(), Type: sec.Type(), Attrs: sec.Attrs()}
		for _, a := range atoms {
			a.Input = ii
			ii.Atoms = append(ii.Atoms, a)
			l.atomSection[a] = key
		}
		st.bySection[sec] = atoms
		l.atoms = append(l.atoms, atoms...)
	}

	// Attach each definition to the atom that carries it. Resolution decided
	// which definition won; this is where the winner acquires its bytes and
	// the losers are marked.
	for sym, d := range l.res.def {
		if d.input != in || d.sym == nil {
			continue
		}
		pos, ok := st.bySymbol[d.sym]
		if !ok {
			// The symbol begins no atom. Either it names a position inside
			// one — which is every symbol but the first when the section was
			// not cut at symbol boundaries — or it has no storage at all.
			var err error
			pos, err = l.positionOf(st, d.sym)
			if err != nil {
				// A definition with no atom is an absolute symbol, which has
				// a value and no storage. Anything else is an object whose
				// symbol table disagrees with its section contents.
				if sym.Class == image.ClassAbsolute {
					continue
				}
				return fmt.Errorf("%s: %w", sym.Name, err)
			}
			st.bySymbol[d.sym] = pos
		}
		sym.Atom, sym.Offset = pos.atom, pos.off
		// Only the symbol that starts the atom names it. A definition inside
		// one — an alt entry, or a later symbol of an uncut section — is
		// carried by that atom but does not own it, and overwriting Sym here
		// would hand the atom's identity to whichever definition was seen
		// last.
		if pos.off == 0 && pos.atom.Sym == nil {
			pos.atom.Sym = sym
		}
		if sym.Root {
			pos.atom.Root = true
		}
	}
	for d, sym := range l.res.coalesced {
		if d.input != in || d.sym == nil {
			continue
		}
		if pos, ok := st.bySymbol[d.sym]; ok {
			a := pos.atom
			// Permanent, and independent of dead-stripping: the atom stays
			// referenceable and references to it are redirected to the
			// winner, rather than the atom being resurrected.
			a.Coalesced = true
			_ = sym
		}
	}
	return nil
}

// positionOf locates a definition that begins no atom.
//
// It exists for the object that does not set MH_SUBSECTIONS_VIA_SYMBOLS.
// There the section is a single atom by definition — the compiler has not
// promised cuts at symbol boundaries are safe — so only the symbol at offset
// zero begins one, and every other definition in that section is a position
// inside it. Such an object is perfectly legal and has to link; the section
// simply lives or dies as a unit under dead-stripping.
//
// The same lookup covers a symbol landing inside a literal or unwind atom,
// where the cuts are made by content and pay no attention to the symbol
// table.
func (l *Linker) positionOf(st *splitState, sym *obj.Symbol) (symPos, error) {
	sec := sym.Sec
	if sec == nil {
		return symPos{}, fmt.Errorf("is defined in no section")
	}
	atoms := st.bySection[sec]
	if len(atoms) == 0 {
		return symPos{}, fmt.Errorf("is defined in %s, which contributes no atoms", sec)
	}
	if sym.Value < sec.Addr {
		return symPos{}, fmt.Errorf("is defined at 0x%x, before %s", sym.Value, sec)
	}
	a, off, err := l.atomAtIndex(atoms, sec, sym.Value-sec.Addr)
	if err != nil {
		return symPos{}, fmt.Errorf("is defined at an address no section covers: %w", err)
	}
	return symPos{atom: a, off: off}, nil
}

// splitSection cuts one object section into atoms.
func (l *Linker) splitSection(in *inputFile, sec *obj.Section) ([]*image.Atom, error) {
	switch {
	case sec.Zerofill():
		return l.splitZerofill(in, sec)
	case isLiteral(sec.Type()):
		return l.splitLiterals(in, sec)
	case sec.SecName() == macho.Sec(SEG_LD, sectCompactUnwind) ||
		sec.Name == macho.SECT_COMPACT_UNWIND:
		return l.splitCompactUnwind(in, sec)
	case sec.Name == macho.SECT_EH_FRAME:
		return l.splitEHFrame(in, sec)
	}
	return l.splitBySymbols(in, sec)
}

// splitBySymbols is the ordinary path: obj.Section.Atoms already implements
// the MH_SUBSECTIONS_VIA_SYMBOLS rules, including alt-entry symbols, aliases
// at one address, and a leading anonymous span.
func (l *Linker) splitBySymbols(in *inputFile, sec *obj.Section) ([]*image.Atom, error) {
	parts, err := sec.Atoms()
	if err != nil {
		return nil, err
	}
	out := make([]*image.Atom, 0, len(parts))
	for i := range parts {
		p := parts[i]
		a := &image.Atom{
			Name:   p.Name(),
			Source: &objSource{sec: sec, off: p.Offset, size: p.Size},
			Align:  atomAlign(sec, p.Offset),
			Root:   p.Root(),
		}
		out = append(out, a)
		in.split.record(sec, p, a)
	}
	return out, nil
}

// record maps every symbol an atom carries to its position within it.
//
// The atom's own symbol and its aliases sit at offset zero by construction.
// An alt-entry symbol names a position strictly inside the atom and does not
// begin one of its own, so it maps to the same atom at the offset its value
// implies; binding it to the atom's start would put every reference to it at
// the wrong address.
func (st *splitState) record(sec *obj.Section, p obj.Atom, a *image.Atom) {
	if p.Sym != nil {
		st.bySymbol[p.Sym] = symPos{atom: a}
	}
	for _, alias := range p.Aliases {
		st.bySymbol[alias] = symPos{atom: a}
	}
	for _, alt := range p.Alt {
		st.bySymbol[alt] = symPos{atom: a, off: alt.Value - sec.Addr - p.Offset}
	}
}

// splitZerofill produces one atom per symbol with no file bytes.
//
// A zerofill section has a size in memory and nothing on disk, so its atoms
// are sized rather than read. Splitting it still matters: __bss is subject to
// dead-stripping like anything else, and one atom for the whole section would
// keep every unreferenced global alive.
func (l *Linker) splitZerofill(in *inputFile, sec *obj.Section) ([]*image.Atom, error) {
	parts, err := sec.Atoms()
	if err != nil {
		return nil, err
	}
	out := make([]*image.Atom, 0, len(parts))
	for i := range parts {
		p := parts[i]
		a := &image.Atom{
			Name:   p.Name(),
			Source: image.ZeroSource{N: p.Size},
			Align:  atomAlign(sec, p.Offset),
			Root:   p.Root(),
		}
		out = append(out, a)
		in.split.record(sec, p, a)
	}
	return out, nil
}

// splitLiterals cuts a literal section by content.
//
// Literals are deduplicated by value rather than by name — two translation
// units that both contain "hello" contribute the same bytes — so the atom's
// identity is its content and the fragment holds the bytes directly.
//
// # The alignment trap
//
// clang emits every cstring into one __TEXT,__cstring regardless of what
// alignment each one needs, expressing the requirement only as .p2align
// padding between them. So the section's alignment is the *maximum* any string
// in it needed, and an individual string's own requirement is not recorded
// anywhere.
//
// Taking the section alignment for every fragment, as this does, is
// conservative and always safe. What is not safe is dropping it: two copies of
// one string from differently-aligned sections deduplicate to a single copy,
// and if the surviving copy takes the weaker alignment then an x86_64 SIMD
// access to it faults at runtime. merge therefore keeps the maximum over all
// copies; see mergeLiterals.
func (l *Linker) splitLiterals(in *inputFile, sec *obj.Section) ([]*image.Atom, error) {
	data, err := sec.Data()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	var spans [][]byte
	if sec.Type() == macho.S_CSTRING_LITERALS {
		spans, err = splitCStrings(data)
	} else {
		spans, err = splitFixed(data, literalSize(sec.Type(), l.be.WordSize()))
	}
	if err != nil {
		return nil, err
	}

	out := make([]*image.Atom, 0, len(spans))
	off := uint64(0)
	for _, s := range spans {
		out = append(out, &image.Atom{
			Source: &image.Fragment{Data: s, Align: sec.Align, Off: off},
			Align:  sec.Align,
		})
		off += uint64(len(s))
	}
	return out, nil
}

// splitCStrings cuts at NUL boundaries, keeping the terminator with its
// string.
//
// An unterminated tail is an error rather than a final implicit string: the
// bytes would be emitted without a NUL and every reader of them would run into
// whatever landed next.
func splitCStrings(data []byte) ([][]byte, error) {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == 0 {
			out = append(out, data[start:i+1])
			start = i + 1
		}
	}
	if start != len(data) {
		return nil, fmt.Errorf("__cstring ends with %d bytes and no terminator", len(data)-start)
	}
	return out, nil
}

// splitFixed cuts into equal-sized elements.
func splitFixed(data []byte, n int) ([][]byte, error) {
	if n <= 0 {
		return [][]byte{data}, nil
	}
	if len(data)%n != 0 {
		return nil, fmt.Errorf("literal section is %d bytes, not a multiple of the %d-byte element size",
			len(data), n)
	}
	out := make([][]byte, 0, len(data)/n)
	for i := 0; i < len(data); i += n {
		out = append(out, data[i:i+n])
	}
	return out, nil
}

// literalSize is the element size of a fixed-width literal section.
func literalSize(t macho.SecType, word int) int {
	switch t {
	case macho.S_4BYTE_LITERALS:
		return 4
	case macho.S_8BYTE_LITERALS:
		return 8
	case macho.S_16BYTE_LITERALS:
		return 16
	case macho.S_LITERAL_POINTERS:
		return word
	}
	return 0
}

func isLiteral(t macho.SecType) bool {
	switch t {
	case macho.S_CSTRING_LITERALS, macho.S_4BYTE_LITERALS, macho.S_8BYTE_LITERALS,
		macho.S_16BYTE_LITERALS, macho.S_LITERAL_POINTERS:
		return true
	}
	return false
}

// sectCompactUnwind and SEG_LD name the section the compiler emits unwind
// entries into. It lives in a segment named __LD that exists only in object
// files and never reaches a linked image.
const (
	SEG_LD            = "__LD"
	sectCompactUnwind = macho.SECT_COMPACT_UNWIND
)

// CompactUnwindEntrySize is the on-disk size of one __compact_unwind entry, by
// pointer width.
//
// The layout is three pointers and two 32-bit words:
//
//	0x00  function address      (pointer, relocated)
//	0x08  function length       (uint32)
//	0x0c  compact encoding      (uint32)
//	0x10  personality routine   (pointer, relocated)
//	0x18  language-specific data (pointer, relocated)
//
// The three relocated fields are why this section cannot be treated as opaque:
// the function address is what associates an entry with the atom it describes,
// and dead-stripping that atom has to take its unwind entry with it.
func CompactUnwindEntrySize(word int) int {
	if word == 8 {
		return 32
	}
	return 20
}

// Field offsets within a 64-bit compact unwind entry.
const (
	cuFunctionOffset    = 0x00
	cuLengthOffset      = 0x08
	cuEncodingOffset    = 0x0c
	cuPersonalityOffset = 0x10
	cuLSDAOffset        = 0x18
)

// splitCompactUnwind cuts the section into fixed-size entries.
func (l *Linker) splitCompactUnwind(in *inputFile, sec *obj.Section) ([]*image.Atom, error) {
	n := CompactUnwindEntrySize(l.be.WordSize())
	if sec.Size%uint64(n) != 0 {
		return nil, fmt.Errorf("__compact_unwind is %d bytes, not a multiple of the %d-byte entry size",
			sec.Size, n)
	}
	count := int(sec.Size) / n
	out := make([]*image.Atom, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, &image.Atom{
			Name:   fmt.Sprintf("__compact_unwind[%d]", i),
			Source: &objSource{sec: sec, off: uint64(i * n), size: uint64(n)},
			Align:  uint32(l.be.WordSize()),
		})
	}
	return out, nil
}

// splitEHFrame cuts at CIE and FDE boundaries.
//
// Each entry begins with a 32-bit length covering everything after it, so the
// entries chain without needing a symbol table. A length of zero is the
// terminator. The word after the length distinguishes the two forms: zero
// means a CIE, and anything else is an FDE whose value is a backward offset to
// its CIE.
//
// # Known gap
//
// An FDE's reference to its function is pc-relative from the FDE's own
// address, which means dead-stripping or reordering anything before it changes
// the value the relocation should have produced. ld64 and lld handle this by
// canonicalizing the reference at split time against a symbol placed at the
// FDE's start. Nothing here does that yet, so an __eh_frame that survives
// dead-stripping unchanged is correct and one that does not is not.
func (l *Linker) splitEHFrame(in *inputFile, sec *obj.Section) ([]*image.Atom, error) {
	data, err := sec.Data()
	if err != nil {
		return nil, err
	}
	var out []*image.Atom
	off := 0
	for off+4 <= len(data) {
		length := binary.LittleEndian.Uint32(data[off:])
		if length == 0 {
			break // terminator
		}
		if length == 0xffffffff {
			return nil, fmt.Errorf("__eh_frame at %d uses 64-bit DWARF, which is unsupported", off)
		}
		size := 4 + int(length)
		if off+size > len(data) {
			return nil, fmt.Errorf("__eh_frame entry at %d claims %d bytes, %d remain",
				off, size, len(data)-off)
		}
		kind := "FDE"
		if off+8 <= len(data) && binary.LittleEndian.Uint32(data[off+4:]) == 0 {
			kind = "CIE"
		}
		out = append(out, &image.Atom{
			Name:   fmt.Sprintf("__eh_frame %s@%d", kind, off),
			Source: &objSource{sec: sec, off: uint64(off), size: uint64(size)},
			Align:  uint32(l.be.WordSize()),
			// A CIE is shared by every FDE that points at it and nothing
			// names it, so it cannot be discovered by walking references. It
			// is a root until FDE-to-CIE edges are modelled.
			Root: kind == "CIE",
		})
		off += size
	}
	return out, nil
}

// atomAlign is an atom's alignment.
//
// The section's alignment is the maximum any atom in it needed, so using it
// for every atom over-aligns some of them. That costs padding and is always
// correct; deriving a weaker per-atom alignment from the atom's offset in the
// input would be wrong the moment the atom moves, which is what layout does.
func atomAlign(sec *obj.Section, off uint64) uint32 {
	if sec.Align == 0 {
		return 1
	}
	return sec.Align
}

// convertRelocs turns an input's on-disk relocations into image.Relocs.
func (l *Linker) convertRelocs(img *image.Image, in *inputFile) error {
	cpu := l.target.CPU
	table := img.Symbols()

	for _, sec := range in.obj.Sections {
		rs, err := sec.Relocs()
		if err != nil {
			return err
		}
		atoms := in.split.bySection[sec]

		// Pending addend from an ARM64_RELOC_ADDEND, which modifies the entry
		// that follows it. It is consumed by the next entry and must not
		// survive past it.
		pending := int64(0)
		havePending := false

		err = obj.RelocPairs(cpu, rs, func(r obj.Reloc, partner *obj.Reloc) error {
			if isAddendReloc(cpu, r.Type) {
				pending, havePending = int64(r.SymbolNum), true
				if partner == nil {
					return fmt.Errorf("%s: ADDEND at 0x%x has no following entry", sec, r.Address)
				}
				// The partner is the entry the addend belongs to; emit it
				// with the addend folded in and report it consumed.
				ir, err := l.makeReloc(in, sec, atoms, *partner, nil, pending, table)
				if err != nil {
					return err
				}
				pending, havePending = 0, false
				return l.attach(in, sec, atoms, uint64(partner.Address), ir)
			}

			add := int64(0)
			if havePending {
				add, pending, havePending = pending, 0, false
			}
			var sub *obj.Reloc
			target := r
			if partner != nil && isSubtractor(cpu, r.Type) {
				// The pair is one difference. SUBTRACTOR names the value to
				// subtract and its partner names the value to add, so the
				// partner is the entry whose type and field the result is
				// written through.
				sub, target = &r, *partner
			}
			ir, err := l.makeReloc(in, sec, atoms, target, sub, add, table)
			if err != nil {
				return err
			}
			return l.attach(in, sec, atoms, uint64(target.Address), ir)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// makeReloc builds one image.Reloc from an on-disk entry.
func (l *Linker) makeReloc(in *inputFile, sec *obj.Section, atoms []*image.Atom,
	r obj.Reloc, sub *obj.Reloc, addend int64, table *image.SymbolTable) (image.Reloc, error) {

	ir := image.Reloc{
		Type:   r.Type,
		Length: r.Length,
		PCRel:  r.PCRel,
		Addend: addend,
	}

	switch {
	case r.Sym != nil && !r.Sym.Ext():
		// An extern relocation naming a symbol with internal linkage is a
		// reference within this object, not a name for resolution to find:
		// the symbol is in the object's table so the assembler could point
		// at it, but it is in no other file's, and interning it would make
		// the link fail on an undefined symbol that is defined right here.
		// clang emits exactly this for a string literal — an l_.str label
		// referenced by a PAGE21/PAGEOFF12 pair — so it is the ordinary
		// case, not a corner.
		//
		// Two objects may each have a local of the same name, which is the
		// other reason the global table is the wrong place for it: the
		// reference has to reach this object's definition and no other.
		pos, ok := in.split.bySymbol[r.Sym]
		if !ok {
			p, err := l.positionOf(in.split, r.Sym)
			if err != nil {
				return ir, fmt.Errorf("%s: relocation at 0x%x names %s, which %w",
					sec, r.Address, r.Sym.Name, err)
			}
			pos = p
			in.split.bySymbol[r.Sym] = pos
		}
		ir.Atom = pos.atom
		ir.Addend = addend + int64(pos.off)
		if addend == 0 {
			// The addend still has to come out of the instruction stream for
			// the kinds that carry it there; becoming an atom reference does
			// not move it. The tail of this function does the same for a
			// symbol reference and skips anything already bound to an atom.
			if data, err := sec.Data(); err == nil {
				probe := ir
				probe.Atom = nil
				if a, ok := l.be.Addend(data, uint64(r.Address), probe); ok {
					ir.Addend += a
				}
			}
		}
	case r.Sym != nil:
		ir.Sym = table.Intern(r.Sym.Name)
	case r.Sec != nil:
		// A section-relative reference names an address, not a symbol. Which
		// atom it lands in depends on where the split fell, so it is resolved
		// to an atom here and the residual offset becomes part of the addend.
		a, delta, err := l.atomAt(in, r.Sec, uint64(r.Address)+uint64(addend))
		if err != nil {
			return ir, fmt.Errorf("%s at 0x%x: %w", sec, r.Address, err)
		}
		ir.Atom = a
		ir.Addend = int64(delta)
	default:
		return ir, fmt.Errorf("%s: relocation at 0x%x names neither a symbol nor a section",
			sec, r.Address)
	}

	if sub != nil {
		if sub.Sym == nil {
			return ir, fmt.Errorf("%s: SUBTRACTOR at 0x%x does not name a symbol", sec, sub.Address)
		}
		ir.Sub = table.Intern(sub.Sym.Name)
	}

	// Recover the addend the compiler left in the instruction stream, for the
	// relocation kinds that carry one there. The backend decides which those
	// are; only it knows the instruction encodings.
	if addend == 0 && ir.Atom == nil {
		data, err := sec.Data()
		if err == nil {
			if a, ok := l.be.Addend(data, uint64(r.Address), ir); ok {
				ir.Addend = a
			}
		}
	}
	return ir, nil
}

// attach hangs a relocation off the atom whose bytes it modifies, with the
// offset rewritten to be atom-relative.
//
// Atom-relative rather than section-relative because an atom moves during
// layout and ordering, and a section-relative offset would have to be
// rewritten every time it did.
func (l *Linker) attach(in *inputFile, sec *obj.Section, atoms []*image.Atom,
	addr uint64, r image.Reloc) error {

	a, off, err := l.atomAtIndex(atoms, sec, addr)
	if err != nil {
		return fmt.Errorf("%s: relocation at 0x%x: %w", sec, addr, err)
	}
	r.Offset = off
	a.Relocs = append(a.Relocs, r)
	return nil
}

// atomAt finds the atom covering an address in a named section.
func (l *Linker) atomAt(in *inputFile, sec *obj.Section, addr uint64) (*image.Atom, uint64, error) {
	if addr < sec.Addr {
		return nil, 0, fmt.Errorf("address 0x%x is before %s", addr, sec)
	}
	return l.atomAtIndex(in.split.bySection[sec], sec, addr-sec.Addr)
}

// atomAtIndex finds the atom covering a section-relative offset.
//
// Atoms are in ascending offset order, so this is a binary search. It has to
// be: a large object has tens of thousands of atoms and every relocation does
// one of these.
func (l *Linker) atomAtIndex(atoms []*image.Atom, sec *obj.Section, off uint64) (*image.Atom, uint64, error) {
	i := sort.Search(len(atoms), func(i int) bool {
		return atomOffset(atoms[i]) > off
	}) - 1
	if i < 0 {
		return nil, 0, fmt.Errorf("offset 0x%x precedes the first atom of %s", off, sec)
	}
	a := atoms[i]
	base := atomOffset(a)
	if off >= base+a.Size() {
		return nil, 0, fmt.Errorf("offset 0x%x falls in no atom of %s", off, sec)
	}
	return a, off - base, nil
}

// atomOffset is an atom's offset within the object section it came from.
//
// A literal atom has one too. Without it every literal in a section claims to
// start at zero, so the binary search below always lands on the first — and a
// symbol or relocation pointing anywhere past it resolves to nothing. Every
// Objective-C image is that case: each selector name in __objc_methname
// carries a label, and each is a separate literal.
func atomOffset(a *image.Atom) uint64 {
	switch s := a.Source.(type) {
	case *objSource:
		return s.off
	case *image.Fragment:
		return s.Off
	}
	return 0
}

func isSubtractor(cpu macho.CPU, typ uint8) bool {
	switch cpu {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32:
		return macho.ARM64Reloc(typ) == macho.ARM64_RELOC_SUBTRACTOR
	case macho.CPU_TYPE_X86_64:
		return macho.X86_64Reloc(typ) == macho.X86_64_RELOC_SUBTRACTOR
	}
	return false
}

func isAddendReloc(cpu macho.CPU, typ uint8) bool {
	switch cpu {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32:
		return macho.ARM64Reloc(typ) == macho.ARM64_RELOC_ADDEND
	}
	return false
}

// objSource is an image.AtomSource backed by a span of an object file section.
//
// The bytes are read once, after Freeze, rather than held from the start. A
// large link reads thousands of objects and most of their content is copied
// straight through; keeping it all in memory from the moment it was parsed
// costs more than reading it again at the point it is written.
type objSource struct {
	sec  *obj.Section
	off  uint64
	size uint64
}

func (s *objSource) Size() uint64   { return s.size }
func (s *objSource) Zerofill() bool { return s.sec.Zerofill() }

func (s *objSource) Bytes() ([]byte, error) {
	e, ok, err := s.sec.Open()
	if err != nil || !ok {
		return nil, err
	}
	return e.Read(int64(s.off), int64(s.size))
}
