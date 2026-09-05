// Package x86_64 is the Intel 64 backend.
//
// It implements backend.Backend and backend.Stubber for CPU_TYPE_X86_64. It
// deliberately does not implement backend.Thunker: a CALL or JMP displacement
// is a signed 32-bit field, so a branch reaches ±2 GiB and no image this tree
// can produce needs range-extension veneers. That is the one structural
// difference from arm64, and it is why Thunker is an optional interface rather
// than part of Backend.
//
// # RIP-relative addressing
//
// Every pc-relative relocation here writes a 32-bit displacement measured from
// the *next* instruction, not from the field being written. Since the
// displacement is the last four bytes of the instruction, the linker computes
// target - (fieldAddr + 4).
//
// That "+4" is an assumption about instruction shape, and X86_64_RELOC_SIGNED_1,
// _2, and _4 are the cases where it does not hold: those name instructions
// with one, two, or four bytes of immediate operand *after* the displacement,
// so RIP is really fieldAddr + 4 + N. What rescues the arithmetic is that such
// a relocation always carries an embedded addend of exactly -N, which cancels
// the difference. The subtraction is therefore correct for every type here,
// but only because the addend came out of the instruction stream. See
// PCRelBias.
//
// # Package name
//
// Go discourages underscores in package names, and `x86_64` has one. The name
// matches the directory, the toolchain arch name, and macho.ArchName's output,
// which is worth more here than the lint.
package x86_64

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
)

// Backend is the x86_64 implementation of backend.Backend.
type Backend struct {
	stubs backend.StubKind

	got  backend.GotShape
	stub backend.StubShape
}

var (
	_ backend.Backend = (*Backend)(nil)
	_ backend.Stubber = (*Backend)(nil)
)

// DispSize is the width of a RIP-relative displacement field. Every
// pc-relative relocation on this architecture writes exactly this many bytes.
const DispSize = 4

func init() { backend.Register(New(backend.StubNonLazy)) }

// New builds an x86_64 backend using the given stub strategy.
//
// Non-lazy is the default and the one to prefer: under chained fixups dyld
// binds the image at load anyway, so lazy binding costs three sections and a
// writable code path for no benefit.
func New(stubs backend.StubKind) *Backend {
	if stubs == backend.StubNone {
		stubs = backend.StubNonLazy
	}
	b := &Backend{stubs: stubs}

	b.got = backend.GotShape{
		// __DATA_CONST so dyld can make it read-only once fixups are applied.
		Name:      macho.Sec(macho.SEG_DATA_CONST, macho.SECT_GOT),
		Type:      macho.S_NON_LAZY_SYMBOL_POINTERS,
		EntrySize: 8,
		Align:     8,
	}
	b.stub = backend.StubShape{
		Kind:  stubs,
		Name:  macho.Sec(macho.SEG_TEXT, macho.SECT_STUBS),
		Type:  macho.S_SYMBOL_STUBS,
		Attrs: macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
		// Six bytes, and unaligned. x86_64 instructions have no alignment
		// requirement, and packing stubs end to end is what ld64 does — an
		// alignment here would insert padding that nothing needs.
		EntrySize: StubSize,
		Align:     1,
	}
	if stubs.Lazy() {
		b.stub.PointerName = macho.Sec(macho.SEG_DATA, macho.SECT_LA_SYMBOL_PTR)
		b.stub.PointerType = macho.S_LAZY_SYMBOL_POINTERS
		b.stub.HelperName = macho.Sec(macho.SEG_TEXT, macho.SECT_STUB_HELPER)
		b.stub.HelperHeaderSize = StubHelperHeaderSize
		b.stub.HelperEntrySize = StubHelperEntrySize
	}

	if err := b.got.Valid(); err != nil {
		panic(err)
	}
	if err := b.stub.Valid(); err != nil {
		panic(err)
	}
	return b
}

func (b *Backend) CPU() macho.CPU       { return macho.CPU_TYPE_X86_64 }
func (b *Backend) SubCPU() macho.SubCPU { return macho.CPU_SUBTYPE_X86_64_ALL }
func (b *Backend) WordSize() int        { return 8 }

// Classify maps an X86_64_RELOC_* value to the Kind link acts on.
//
// SIGNED and its three biased variants collapse to one Kind. The bias is a
// property of the instruction's trailing bytes, not of what the linker has to
// arrange, and it is already accounted for in the addend by the time a Kind
// matters.
func (b *Backend) Classify(typ uint8) backend.Kind {
	switch macho.X86_64Reloc(typ) {
	case macho.X86_64_RELOC_UNSIGNED:
		return backend.KindAbsolute
	case macho.X86_64_RELOC_SUBTRACTOR:
		return backend.KindSubtractor
	case macho.X86_64_RELOC_BRANCH:
		return backend.KindBranch
	case macho.X86_64_RELOC_SIGNED,
		macho.X86_64_RELOC_SIGNED_1,
		macho.X86_64_RELOC_SIGNED_2,
		macho.X86_64_RELOC_SIGNED_4:
		return backend.KindSigned
	case macho.X86_64_RELOC_GOT_LOAD:
		return backend.KindGOTLoad
	case macho.X86_64_RELOC_GOT:
		return backend.KindGOT
	case macho.X86_64_RELOC_TLV:
		return backend.KindTLV
	}
	return backend.KindUnknown
}

// PCRelBias returns the number of bytes that follow the displacement field
// inside the instruction a relocation applies to.
//
// It is zero for every type except X86_64_RELOC_SIGNED_1, _2, and _4, where it
// is 1, 2, and 4. A relocation of those types must carry an embedded addend of
// exactly the negation of this, and Addend recovers it from the instruction
// stream. The function is exported because anything that *synthesizes* one of
// these relocations rather than reading it has to supply that addend itself,
// and there is nothing in the format that would catch the omission — the
// result is an address off by one, two, or four bytes.
func PCRelBias(typ uint8) int {
	switch macho.X86_64Reloc(typ) {
	case macho.X86_64_RELOC_SIGNED_1:
		return 1
	case macho.X86_64_RELOC_SIGNED_2:
		return 2
	case macho.X86_64_RELOC_SIGNED_4:
		return 4
	}
	return 0
}

// Addend recovers a relocation's addend from the bytes it applies to.
//
// Unlike arm64, which routes addends through a separate ARM64_RELOC_ADDEND
// entry, every x86_64 relocation carries its addend in the field itself. For
// the pc-relative types that field is a signed 32-bit displacement; for
// UNSIGNED and SUBTRACTOR it is the full 4 or 8 byte value.
func (b *Backend) Addend(content []byte, off uint64, r image.Reloc) (int64, bool) {
	n := uint64(r.Length.Bytes())
	if off > uint64(len(content)) || n > uint64(len(content))-off {
		return 0, false
	}
	switch b.Classify(r.Type) {
	case backend.KindUnknown:
		return 0, false
	}
	switch r.Length {
	case macho.RelocLong:
		return int64(int32(binary.LittleEndian.Uint32(content[off:]))), true
	case macho.RelocQuad:
		return int64(binary.LittleEndian.Uint64(content[off:])), true
	}
	return 0, false
}

// Scan records what the link must synthesize.
func (b *Backend) Scan(img *image.Image, reqs *backend.Reqs) error {
	for _, sec := range img.Sections() {
		for _, atom := range sec.LiveAtoms() {
			for _, r := range atom.Relocs {
				if err := b.scanReloc(img, atom, r, reqs); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (b *Backend) scanReloc(img *image.Image, atom *image.Atom, r image.Reloc, reqs *backend.Reqs) error {
	kind := b.Classify(r.Type)
	if kind == backend.KindUnknown {
		return fmt.Errorf("%w: r_type %d at %s+0x%x",
			backend.ErrUnsupportedReloc, r.Type, atom, r.Offset)
	}

	switch {
	case kind.NeedsGOT():
		if r.Sym == nil {
			return fmt.Errorf("x86_64: GOT relocation at %s+0x%x names no symbol", atom, r.Offset)
		}
		reqs.GOT(r.Sym)
		return nil

	case kind.NeedsTLV():
		if r.Sym == nil {
			return fmt.Errorf("x86_64: TLV relocation at %s+0x%x names no symbol", atom, r.Offset)
		}
		reqs.TLV(r.Sym)
		return nil

	case kind.IsBranch():
		// A CALL displacement is not a bind site, so a call into a dylib goes
		// through a stub. A call to something defined here is a direct branch
		// — and unlike arm64, it can never be out of range.
		if r.Sym != nil && r.Sym.Class == image.ClassImport {
			reqs.Stub(r.Sym)
		}
		return nil

	case !kind.IsPointer():
		return nil
	}

	// A difference between two addresses in this image is a link-time
	// constant: it does not slide, so it is neither a rebase nor a bind.
	if r.Sub != nil {
		return nil
	}

	// Nor does a thread-local descriptor's offset field, which is a
	// distance from the start of the template region rather than an
	// address. Registering a rebase for it would have dyld slide a
	// number that is then added to the thread's block base.
	if backend.IsTLVTemplateRef(atom, r) {
		return nil
	}
	if r.Length != macho.RelocQuad {
		// A 32-bit absolute cannot be a fixup in a 64-bit image — dyld has no
		// pointer format for one, and the value would be truncated at load.
		// Such a relocation is legitimate only against a link-time constant,
		// which is the r.Sub case handled above.
		return fmt.Errorf("x86_64: %d-byte absolute relocation at %s+0x%x cannot be rebased or bound",
			r.Length.Bytes(), atom, r.Offset)
	}

	if r.Sym != nil && !r.Sym.Defined() {
		return reqs.AddBind(backend.Bind{
			Atom:   atom,
			Offset: r.Offset,
			Sym:    r.Sym,
			Addend: r.Addend,
			Weak:   r.Sym.WeakRef,
		})
	}
	return reqs.AddRebase(backend.Rebase{Atom: atom, Offset: r.Offset})
}

// Apply writes one relocation.
func (b *Backend) Apply(s *backend.Site, r image.Reloc) error {
	kind := b.Classify(r.Type)
	if !kind.WritesField() {
		return nil
	}

	value, err := b.value(s, r, kind)
	if err != nil {
		return err
	}

	if kind == backend.KindAbsolute {
		switch r.Length {
		case macho.RelocQuad:
			return s.Write64(r.Offset, value)
		case macho.RelocLong:
			if err := s.CheckUnsigned(b.name(r), r.Offset, value, 32); err != nil {
				return err
			}
			return s.Write32(r.Offset, uint32(value))
		}
		return fmt.Errorf("x86_64: %v with r_length %d at %s+0x%x",
			macho.X86_64Reloc(r.Type), r.Length, s.Atom, r.Offset)
	}

	// Everything else is a RIP-relative displacement. RIP has advanced past
	// the four-byte field by the time the instruction executes, so the
	// displacement is measured from the end of it.
	//
	// For SIGNED_1/2/4 the instruction continues past the field, but the
	// addend already folded into value is -1, -2, or -4 and accounts for
	// exactly that. See the package comment.
	pc := s.PC(r.Offset)
	disp := int64(value) - int64(pc) - DispSize
	if err := s.CheckSigned(b.name(r), r.Offset, disp, 32, 0); err != nil {
		return err
	}
	return s.Write32(r.Offset, uint32(int32(disp)))
}

// value resolves the address a relocation refers to: the GOT or TLV slot for
// an indirect kind, the stub for a branch to an import, the symbol itself
// otherwise.
func (b *Backend) value(s *backend.Site, r image.Reloc, kind backend.Kind) (uint64, error) {
	switch {
	case kind.NeedsGOT():
		v, err := b.slotAddr(s, r.Sym, b.got.Name, uint64(b.got.EntrySize), s.Reqs.GOTIndex, "GOT")
		if err != nil {
			return 0, err
		}
		return v + uint64(r.Addend), nil

	case kind.NeedsTLV():
		v, err := b.slotAddr(s, r.Sym, macho.Sec(macho.SEG_DATA, macho.SECT_THREAD_PTRS),
			8, s.Reqs.TLVIndex, "thread-local")
		if err != nil {
			return 0, err
		}
		return v + uint64(r.Addend), nil
	}

	if kind.IsBranch() && r.Sym != nil && r.Sym.Class == image.ClassImport {
		i, ok := s.Reqs.StubIndex(r.Sym)
		if !ok {
			return 0, fmt.Errorf("x86_64: %s is imported and called but has no stub", r.Sym.Name)
		}
		base, ok := s.SectionAddr(b.stub.Name)
		if !ok {
			return 0, fmt.Errorf("x86_64: the image has no %s section", b.stub.Name)
		}
		return b.stub.Entry(base, i), nil
	}

	// A pointer to an import has no address in this image. Scan
	// registered a bind for it, so dyld is what writes the address at
	// load — and the chained-fixup encoder overwrites this field with a
	// chain entry before that. What goes here now is the addend the bind
	// carries, because resolving a target that does not exist is the
	// alternative, and it fails.
	//
	// The condition mirrors Scan's exactly. The two have to agree: a
	// site Scan registered and this resolved would be written twice with
	// different answers, and one Scan skipped and this resolved would
	// ask an unbound symbol for its address.
	if kind.IsPointer() && r.Sub == nil && r.Sym != nil && !r.Sym.Defined() {
		return uint64(r.Addend), nil
	}

	// A thread-local descriptor's offset field holds the template's
	// distance from the region base, which is a link-time constant and
	// not the address the relocation appears to name.
	if off, ok := backend.TLVTemplateOffset(s.Img, s.Atom, r); ok {
		return off, nil
	}

	v, err := r.Target()
	if err != nil {
		return 0, err
	}
	if r.Sub != nil {
		if !r.Sub.Bound {
			return 0, fmt.Errorf("x86_64: subtrahend %s is unbound", r.Sub.Name)
		}
		v -= r.Sub.Value
	}
	return v, nil
}

func (b *Backend) slotAddr(s *backend.Site, sym *image.Sym, name macho.SecName,
	entry uint64, index func(*image.Sym) (int, bool), what string) (uint64, error) {

	if sym == nil {
		return 0, fmt.Errorf("x86_64: %s relocation names no symbol", what)
	}
	i, ok := index(sym)
	if !ok {
		return 0, fmt.Errorf("x86_64: %s has no %s slot; Scan did not reserve one", sym.Name, what)
	}
	base, ok := s.SectionAddr(name)
	if !ok {
		return 0, fmt.Errorf("x86_64: the image has no %s section", name)
	}
	return base + uint64(i)*entry, nil
}

func (b *Backend) name(r image.Reloc) string { return macho.X86_64Reloc(r.Type).String() }