package link

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
	"github.com/vertex-language/macho/internal/format"
)

// Address and file-offset assignment, and the one fixpoint in the link.
//
// # Why this converges
//
// Two things feed back. The size of the load-command block is an input to
// address assignment, because __TEXT starts at file offset 0 and contains it —
// and the block's size depends on how many segments and sections assignment
// produced. And a branch that was in range last round may not be this round,
// because a thunk added in between pushed its target further away.
//
// Both are monotonic. Thunks are only ever added, never removed, and a
// relaxation only ever shrinks a sequence. So the loop settles, usually in two
// rounds: one to discover the sizes, one to confirm nothing moved. The bound
// exists to turn a backend that oscillates into an error rather than a hang.
//
// # What is not assigned here
//
// __LINKEDIT. Its contents are produced by unwind, fixups, and linkedit, all
// of which need final addresses, and its size feeds back into nothing except
// the total file size — dyld rejects an image with anything after __LINKEDIT,
// so there is nothing downstream of it to move. commit places it, once,
// after those steps have run.

// dyldPath is the dynamic linker every image this tree produces names.
const dyldPath = "/usr/lib/dyld"

func (l *Linker) layout(img *image.Image) error {
	for round := 1; ; round++ {
		if err := l.assignAddresses(img); err != nil {
			return err
		}
		if err := img.BindReserved(); err != nil {
			return err
		}
		if err := l.bindSymbols(img); err != nil {
			return err
		}

		grew, err := l.growThunks(img)
		if err != nil {
			return err
		}
		relaxed, err := l.relax(img)
		if err != nil {
			return err
		}
		if !grew && !relaxed {
			return nil
		}
		if round >= l.opts.MaxLayoutRounds {
			return fmt.Errorf("%w: %d rounds, still moving (thunks=%v relaxed=%v)",
				ErrLayoutDivergence, round, grew, relaxed)
		}
	}
}

// assignAddresses places every segment, section, and atom.
//
// The invariant that makes a segment mappable is that a section's file offset
// minus the segment's equals its address minus the segment's. That holds here
// because both cursors advance by the same page-aligned amount for every
// segment, so a file offset is just an address minus the image base — which is
// asserted rather than assumed.
func (l *Linker) assignAddresses(img *image.Image) error {
	// A thunk added last round may have created __TEXT,__thunks, which needs
	// an ordinal before any symbol referring to it is emitted.
	if err := img.OrderSections(); err != nil {
		return err
	}

	page := img.PageSize()
	base := img.BaseAddress()

	_, cmdSize := l.commands(img)
	hdr := uint64(format.HeaderSize(img.Width())) + cmdSize
	if err := img.SetHeaderSize(hdr); err != nil {
		return err
	}

	addr := base
	for _, seg := range img.Segments() {
		switch seg.Name {
		case macho.SEG_PAGEZERO:
			// Address zero, no file content, and the only segment whose
			// address is legitimately zero — which is why image tracks
			// "assigned" as a flag rather than testing for a zero address.
			if err := seg.SetPlacement(0, img.PageZeroSize(), 0, 0); err != nil {
				return err
			}
			continue
		case macho.SEG_LINKEDIT:
			// Sized in commit. Placed provisionally so that a caller reading
			// the segment mid-pipeline gets its address rather than an error.
			l.leAddr, l.leOff = alignUp(addr, page), alignUp(addr, page)-base
			if err := seg.SetPlacement(l.leAddr, page, l.leOff, 0); err != nil {
				return err
			}
			continue
		}

		if seg.Name == macho.SEG_DATA_CONST || seg.Name == macho.SEG_AUTH_CONST {
			// Writable at the page-protection level so fixups can be applied,
			// but SG_READ_ONLY tells dyld to mprotect it read-only once they
			// are — the whole reason these segments exist apart from __DATA.
			// A modern dyld refuses to load an image where they claim this
			// name without also claiming the flag.
			seg.Flags |= macho.SG_READ_ONLY
		}

		segAddr := alignUp(addr, page)
		segOff := segAddr - base

		cursor := segAddr
		if seg.Name == macho.SEG_TEXT {
			// The header and the load commands are the front of __TEXT and
			// belong to no section. Nothing else in the format works this
			// way, and it is the reason the load-command size closes a loop.
			cursor += hdr
		}
		fileEnd := segOff + (cursor - segAddr)

		for _, sec := range seg.Sections() {
			al := uint64(sec.Align)
			if al == 0 {
				al = 1
			}
			cursor = alignUp(cursor, al)

			size := placeAtoms(sec, cursor)

			var secOff uint64
			if !sec.Zerofill() {
				secOff = segOff + (cursor - segAddr)
				if end := secOff + size; end > fileEnd {
					fileEnd = end
				}
			}
			if err := sec.SetPlacement(cursor, size, secOff); err != nil {
				return err
			}
			cursor += size
		}

		vmSize := alignUp(cursor-segAddr, page)
		fileSize := alignUp(fileEnd-segOff, page)
		if err := seg.SetPlacement(segAddr, vmSize, segOff, fileSize); err != nil {
			return err
		}
		addr = segAddr + vmSize
	}
	return nil
}

// placeAtoms assigns each live atom its offset within a section and returns
// the section's size.
//
// A section's own alignment is the maximum over its atoms, which image
// maintains as atoms are added, so aligning the section base is not enough on
// its own — an atom needing 16 bytes behind one needing 1 still has to be
// pushed. Offsets are section-relative because the section moves during the
// fixpoint and the atoms do not move within it.
func placeAtoms(sec *image.Section, base uint64) uint64 {
	cur := base
	for _, a := range sec.LiveAtoms() {
		al := uint64(a.Align)
		if al == 0 {
			al = 1
		}
		cur = alignUp(cur, al)
		a.Offset = cur - base
		cur += a.Size()
	}
	return cur - base
}

// bindSymbols gives every definition its final address.
//
// Bound is set rather than the address being compared against zero: zero is a
// legal address in a dylib, and a relocation against an unbound symbol has to
// be an error rather than a write of zero that links and faults.
func (l *Linker) bindSymbols(img *image.Image) error {
	for _, sym := range img.Symbols().All() {
		switch sym.Class {
		case image.ClassDefined:
			if sym.Reserved {
				continue // BindReserved owns these; their value is the base.
			}
			if sym.Atom == nil {
				// The one way to get here is a common symbol: resolve
				// promotes it to ClassDefined and leaves split to create the
				// zerofill storage, which split does not do. Named rather
				// than tolerated, because a defined symbol with no address is
				// a bind of zero everywhere it is used.
				return fmt.Errorf("link: %s is defined with no atom; "+
					"a tentative definition needs __DATA,__common storage (split.go)",
					sym.Name)
			}
			if sym.Atom.Coalesced || !sym.Atom.Live {
				continue
			}
			v, err := sym.Atom.Addr()
			if err != nil {
				return err
			}
			// Offset is zero for the symbol that begins the atom, which is
			// the ordinary case. It is the distance into the atom for an
			// alt entry, and for a definition in a section that was never
			// cut at symbol boundaries.
			sym.Value, sym.Bound = v+sym.Offset, true

		case image.ClassAbsolute:
			sym.Bound = true
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Thunks
// --------------------------------------------------------------------------

// thunkKey identifies what a thunk reaches. A thunk is shared by every branch
// that needs to reach the same place, which is what keeps a hot function from
// growing one veneer per caller.
type thunkKey struct {
	sym  *image.Sym
	atom *image.Atom
}

// thunkRec is a placed thunk and what it reaches. The bytes are written after
// Freeze, when the target's address is final.
type thunkRec struct {
	atom *image.Atom
	src  *image.RawSource
	key  thunkKey
}

// growThunks retargets out-of-range branches through veneers.
//
// It reports whether it added any, which is one of the two things that keeps
// the fixpoint going. A thunk is inserted by rewriting the relocation to point
// at the thunk atom, so the backend's Apply never learns a veneer was
// involved — it encodes an ordinary in-range branch.
//
// # Known gap
//
// All thunks land in one __TEXT,__thunks section. That is sufficient while
// __TEXT is smaller than the branch reach, and it fails for an image large
// enough to need islands distributed through the text — at which point a
// branch cannot reach its own thunk. The ADRP inside a thunk reaches ±4 GiB,
// so the thunk always reaches its target; it is the branch-to-thunk hop that
// runs out first. Distributed islands are the next step, and until then the
// backend's range check reports the failure rather than encoding silently.
func (l *Linker) growThunks(img *image.Image) (bool, error) {
	th, ok := backend.AsThunker(l.be)
	if !ok {
		return false, nil
	}
	shape := th.ThunkShape()
	changed := false

	for _, sec := range img.Sections() {
		for _, atom := range sec.LiveAtoms() {
			if len(atom.Relocs) == 0 {
				continue
			}
			from, err := atom.Addr()
			if err != nil {
				return false, err
			}
			for i := range atom.Relocs {
				r := &atom.Relocs[i]
				if l.be.Classify(r.Type) != backend.KindBranch {
					continue
				}
				// A branch to an import goes to a stub, whose address the
				// backend computes at Apply time. Range-checking that hop
				// needs the stub section's address here and is not done:
				// __stubs sits in __TEXT beside the code that calls it, so it
				// is out of reach only in an image that already needs
				// distributed islands.
				if r.Sym != nil && r.Sym.Class == image.ClassImport {
					continue
				}
				target, err := r.Target()
				if err != nil {
					return false, err
				}
				if shape.InRange(from+r.Offset, target) {
					continue
				}
				t, err := l.thunkFor(img, shape, r)
				if err != nil {
					return false, err
				}
				// The branch now names the thunk and nothing else. Clearing
				// the addend matters: it was folded into the target address
				// the thunk materializes, and applying it twice would land
				// past the function.
				r.Atom, r.Sym, r.Addend = t, nil, 0
				r.Sub, r.SubAtom, r.SubAddend = nil, nil, 0
				changed = true
			}
		}
	}
	return changed, nil
}

func (l *Linker) thunkFor(img *image.Image, shape backend.ThunkShape, r *image.Reloc) (*image.Atom, error) {
	key := thunkKey{sym: r.Sym, atom: r.Atom}
	if t, ok := l.thunks[key]; ok {
		return t, nil
	}
	sec, err := img.Section(image.SectionKey{
		Name:  macho.Sec(macho.SEG_TEXT, sectThunks),
		Type:  macho.S_REGULAR,
		Attrs: macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
	})
	if err != nil {
		return nil, err
	}

	name := "<thunk>"
	switch {
	case r.Sym != nil:
		name = "<thunk " + r.Sym.Name + ">"
	case r.Atom != nil:
		name = "<thunk " + r.Atom.String() + ">"
	}

	src := image.NewRawSource(uint64(shape.Size))
	a := &image.Atom{Name: name, Source: src, Align: shape.Align, Live: true, Root: true}
	if err := sec.AddAtom(a); err != nil {
		return nil, err
	}
	if l.thunks == nil {
		l.thunks = make(map[thunkKey]*image.Atom)
	}
	l.thunks[key] = a
	l.thunkList = append(l.thunkList, thunkRec{atom: a, src: src, key: key})
	l.atoms = append(l.atoms, a)
	return a, nil
}

// --------------------------------------------------------------------------
// Load-command sizing
// --------------------------------------------------------------------------

// commands returns the number of load commands and the size of the block.
//
// This is the feedback edge: the block sits inside __TEXT at file offset 0, so
// its size decides where the first section lands.
//
// emit.go must emit exactly this list, in an order of its own choosing — the
// format finds commands by walking, not by position — but with exactly these
// members and sizes. There is no mechanism enforcing that. Until emit exists
// and a golden test diffs the result against otool -l, this function and that
// one are two descriptions of one thing.
func (l *Linker) commands(img *image.Image) (uint32, uint64) {
	w := img.Width()
	var n uint32
	var size uint64
	add := func(k int) { n++; size += uint64(k) }
	str := func(fixed int, s string) {
		add(int(alignUp(uint64(fixed+len(s)+1), uint64(format.CmdAlign(w)))))
	}

	for _, seg := range img.Segments() {
		add(format.SegmentCmdSize(w) + len(seg.Sections())*format.SectionSize(w))
	}

	str(format.DylinkerCmdSize, dyldPath)
	add(format.SymtabSize)
	add(format.DysymtabSize)
	add(format.UUIDSize)
	add(format.BuildVersionSize + format.BuildToolVersionSize) // one entry: ld
	add(format.SourceVersionSize)

	switch l.opts.Output {
	case OutputDylib:
		str(format.DylibCmdSize, l.opts.InstallName)
	default:
		add(format.EntryPointSize)
	}
	for _, in := range l.libs {
		if l.opts.DeadStripDylibs && !in.used {
			continue
		}
		str(format.DylibCmdSize, in.lib.InstallName())
	}
	for _, p := range l.opts.RPaths {
		str(format.DylinkerCmdSize, p)
	}

	// The __LINKEDIT descriptors. Chained fixups and the export trie replace
	// LC_DYLD_INFO_ONLY; both are emitted unconditionally, since a command
	// with a zero size says "no fixups" unambiguously and an absent one makes
	// older tools guess.
	add(format.LinkeditDataSize) // LC_DYLD_CHAINED_FIXUPS
	add(format.LinkeditDataSize) // LC_DYLD_EXPORTS_TRIE
	add(format.LinkeditDataSize) // LC_FUNCTION_STARTS
	add(format.LinkeditDataSize) // LC_DATA_IN_CODE
	add(format.LinkeditDataSize) // LC_CODE_SIGNATURE
	return n, size
}

// --------------------------------------------------------------------------
// __LINKEDIT and the commit
// --------------------------------------------------------------------------

// linkeditPlan is what __LINKEDIT will contain.
//
// Each step that builds a table fills in its field and never chooses an
// offset; placement happens once, here, in one order. The order is ld64's —
// fixups, exports, function starts, data-in-code, symbols, indirect symbols,
// strings, signature — which the format does not require and every tool
// nonetheless expects to see, so matching it costs nothing and avoids
// discovering which tool depends on it the hard way.
type linkeditPlan struct {
	ChainedFixups   []byte
	ExportTrie      []byte
	FunctionStarts  []byte
	DataInCode      []byte
	Symtab          []byte
	IndirectSymbols []byte
	Strtab          []byte

	// offsets holds each table's absolute file offset, in the same order as
	// tables(), filled in by commit once __LINKEDIT is placed. A load command
	// that needs where a table landed reads it back through at, rather than
	// recomputing the layout commit already did.
	offsets [7]uint64
}

func (p *linkeditPlan) tables() [][]byte {
	return [][]byte{
		p.ChainedFixups, p.ExportTrie, p.FunctionStarts, p.DataInCode,
		p.Symtab, p.IndirectSymbols, p.Strtab,
	}
}

// at returns table i's absolute file offset and size, as placed by commit.
func (p *linkeditPlan) at(i int) (uint64, uint32) {
	return p.offsets[i], uint32(len(p.tables()[i]))
}

// commit sizes __LINKEDIT, reserves the signature, and freezes the image.
//
// After this the buffer exists and nothing may be resized. It runs at the top
// of contents rather than at the end of layout because the tables above are
// produced by steps that need final addresses.
func (l *Linker) commit(img *image.Image) error {
	word := uint64(l.be.WordSize())
	page := img.PageSize()

	off := l.leOff
	for i, t := range l.le.tables() {
		off = alignUp(off, word)
		l.le.offsets[i] = off
		off += uint64(len(t))
	}

	// The signature is last in __LINKEDIT and therefore last in the file.
	// The CodeDirectory hashes everything before it, which is what makes
	// "nothing may follow" a correctness property rather than a convention.
	sigOff := alignUp(off, 16)
	sigSize := codeSignatureSize(sigOff, l.signingIdentifier())
	total := sigOff + sigSize

	seg := img.FindSegment(macho.SEG_LINKEDIT)
	if seg == nil {
		return fmt.Errorf("link: the image has no %s segment", macho.SEG_LINKEDIT)
	}
	if err := seg.SetPlacement(l.leAddr, alignUp(total-l.leOff, page), l.leOff, total-l.leOff); err != nil {
		return err
	}
	if err := img.SetCodeSignature(sigOff, sigSize); err != nil {
		return err
	}
	if err := img.SetSize(total); err != nil {
		return err
	}
	if err := img.Freeze(); err != nil {
		return err
	}
	return l.writeLinkedit(img)
}

// writeLinkedit copies every __LINKEDIT table into the frozen buffer at the
// offsets commit just assigned. It has to run after Freeze, since nothing may
// be written before the buffer exists.
func (l *Linker) writeLinkedit(img *image.Image) error {
	for i, t := range l.le.tables() {
		if len(t) == 0 {
			continue
		}
		off, _ := l.le.at(i)
		if err := img.WriteAt(off, t); err != nil {
			return err
		}
	}
	return nil
}

// signingIdentifier is the name the CodeDirectory records.
func (l *Linker) signingIdentifier() string {
	if l.opts.InstallName != "" {
		return l.opts.InstallName
	}
	return l.opts.Entry
}

// codeSignatureSize reserves space for an ad-hoc signature.
//
// An arm64 macOS binary will not execute unsigned, so the slot is not
// optional. The size has to be reserved before the bytes exist, because the
// hashes cover the load commands that describe the slot — so this is an
// upper bound and the blob's own length fields absorb the slack.
//
// It must be at least what codesign actually emits. A golden test against
// `codesign -dvvv` is the only thing that can hold that; until one exists this
// is generous on purpose.
func codeSignatureSize(fileSize uint64, identifier string) uint64 {
	const (
		pageSize    = 4096 // the CodeDirectory's hash granularity, not the VM page
		hashSize    = 32   // SHA-256
		specialHash = 8    // special slots, generously
		superBlob   = 12 + 4*8
		codeDir     = 128
		requirement = 64
		cmsEmpty    = 8
	)
	slots := (fileSize + pageSize - 1) / pageSize
	n := uint64(superBlob) + codeDir + uint64(len(identifier)) + 1 +
		(slots+specialHash)*hashSize + requirement + cmsEmpty
	return alignUp(n, 16)
}

// alignUp rounds v up to a multiple of n, which must be a power of two.
func alignUp(v, n uint64) uint64 {
	if n <= 1 {
		return v
	}
	return (v + n - 1) &^ (n - 1)
}