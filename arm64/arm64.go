// Package arm64 is the AArch64 backend.
//
// It implements backend.Backend for CPU_TYPE_ARM64, and exports the pieces
// arm64e and arm64_32 need so that three nearly identical backends are not
// three copies of the same instruction encoders. The variants differ in
// pointer width and in pointer authentication, not in how a BRANCH26 is
// encoded.
//
// # What is here and what is not
//
// Relocation application, stub and GOT generation, and range-extension thunks
// are implemented. Linker optimization hints are not: nothing in this package
// implements backend.Relaxer, so the AdrpAdd -> Adr/Nop rewriting that
// obj/loh.go reads hints for still does not happen. That is a pure
// optimization and it needs a correct linker first, which is where the README
// puts it.
//
// GOT loads are also not relaxed. When a GOT_LOAD relocation turns out to
// reference a symbol defined in this image, the LDR can become an ADD and the
// GOT slot disappears — the instruction check for it is in insn.go and
// documented — but doing so means Scan must decide, before any address exists,
// which slots will survive, and a slot wrongly elided is an image that faults.
// Every GOT_LOAD therefore gets a slot. The cost is eight bytes per symbol.
//
// # Concurrency
//
// A Backend is immutable after New and holds no per-link state, so one
// registered instance serves any number of concurrent links. Everything
// mutable lives in the image and the Reqs the caller passes in.
package arm64

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
)

// Config describes one AArch64 variant.
//
// It exists so arm64e and arm64_32 can construct a Backend rather than
// duplicating this package. The alternative — an internal/arm64common package
// — would put a third package in the tree for the sake of two constants.
type Config struct {
	CPU    macho.CPU
	SubCPU macho.SubCPU

	// WordSize is the pointer size in bytes: 8 for arm64 and arm64e, 4 for
	// arm64_32. backend.Register checks it against the CPU's width.
	WordSize int

	// Stubs selects lazy or non-lazy stubs. Non-lazy is the default and the
	// one to prefer: under chained fixups dyld binds the whole image at load
	// anyway, so lazy binding buys nothing and costs three sections and a
	// writable code path.
	Stubs backend.StubKind

	// PtrAuth, when non-nil, makes this backend a backend.Signer. Only arm64e
	// sets it.
	PtrAuth func(r image.Reloc) (backend.PtrAuth, bool)
}

// Backend is the AArch64 implementation of backend.Backend.
type Backend struct {
	cfg Config

	got   backend.GotShape
	stub  backend.StubShape
	thunk backend.ThunkShape
}

// Compile-time assertions. If an interface here gains a method, this is where
// the build breaks, rather than at a type assertion inside link that would
// simply report the optional interface as unimplemented and silently skip it.
var (
	_ backend.Backend = (*Backend)(nil)
	_ backend.Stubber = (*Backend)(nil)
	_ backend.Thunker = (*Backend)(nil)
)

func init() {
	backend.Register(New(Config{
		CPU:      macho.CPU_TYPE_ARM64,
		SubCPU:   macho.CPU_SUBTYPE_ARM64_ALL,
		WordSize: 8,
		Stubs:    backend.StubNonLazy,
	}))
}

// New builds a backend for one AArch64 variant.
//
// It panics on a configuration that cannot describe a real file — a word size
// that disagrees with the cputype's width, or a shape that fails its own
// validation. These are build-time constants in the caller, so a panic at init
// is the right place for them to surface.
func New(c Config) *Backend {
	if c.WordSize != 4 && c.WordSize != 8 {
		panic(fmt.Sprintf("arm64: word size %d must be 4 or 8", c.WordSize))
	}
	if c.Stubs == backend.StubNone {
		c.Stubs = backend.StubNonLazy
	}

	b := &Backend{cfg: c}
	b.got = backend.GotShape{
		// The GOT lives in __DATA_CONST so dyld can make it read-only once
		// fixups are applied. Putting it in __DATA links and runs, and gives
		// up the hardening without saying so.
		Name:      macho.Sec(macho.SEG_DATA_CONST, macho.SECT_GOT),
		Type:      macho.S_NON_LAZY_SYMBOL_POINTERS,
		EntrySize: uint32(c.WordSize),
		Align:     uint32(c.WordSize),
	}
	b.stub = backend.StubShape{
		Kind:      c.Stubs,
		Name:      macho.Sec(macho.SEG_TEXT, macho.SECT_STUBS),
		Type:      macho.S_SYMBOL_STUBS,
		Attrs:     macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
		EntrySize: StubSize,
		Align:     4,
	}
	if c.Stubs.Lazy() {
		b.stub.PointerName = macho.Sec(macho.SEG_DATA, macho.SECT_LA_SYMBOL_PTR)
		b.stub.PointerType = macho.S_LAZY_SYMBOL_POINTERS
		b.stub.HelperName = macho.Sec(macho.SEG_TEXT, macho.SECT_STUB_HELPER)
		b.stub.HelperHeaderSize = StubHelperHeaderSize
		b.stub.HelperEntrySize = StubHelperEntrySize
	}
	b.thunk = backend.ThunkShape{
		Size:  ThunkSize,
		Align: 4,
		// A BRANCH26 immediate is 26 bits of two's complement, implicitly
		// scaled by 4. That reaches one instruction further backwards than
		// forwards, and collapsing the two into one number either wastes
		// thunks or overflows at the far edge.
		Forward:  BranchReach - 4,
		Backward: BranchReach,
	}

	if err := b.got.Valid(); err != nil {
		panic(err)
	}
	if err := b.stub.Valid(); err != nil {
		panic(err)
	}
	if err := b.thunk.Valid(); err != nil {
		panic(err)
	}
	return b
}

// BranchReach is the magnitude of the largest negative displacement a BRANCH26
// can encode: 4 * 2^25, or 128 MiB.
const BranchReach = 128 << 20

func (b *Backend) CPU() macho.CPU       { return b.cfg.CPU }
func (b *Backend) SubCPU() macho.SubCPU { return b.cfg.SubCPU }
func (b *Backend) WordSize() int        { return b.cfg.WordSize }

// PtrAuth implements backend.Signer, and is present only when the variant
// supplied a schema function. A nil-schema backend still has the method, so
// AsSigner would succeed on it — which is why the assertion below is
// conditional and link must check the bool this returns, not just the
// interface.
func (b *Backend) PtrAuth(r image.Reloc) (backend.PtrAuth, bool) {
	if b.cfg.PtrAuth == nil {
		return backend.PtrAuth{}, false
	}
	return b.cfg.PtrAuth(r)
}

// Classify maps an ARM64_RELOC_* value to the Kind link acts on.
func (b *Backend) Classify(typ uint8) backend.Kind {
	switch macho.ARM64Reloc(typ) {
	case macho.ARM64_RELOC_UNSIGNED:
		return backend.KindAbsolute
	case macho.ARM64_RELOC_SUBTRACTOR:
		return backend.KindSubtractor
	case macho.ARM64_RELOC_BRANCH26:
		return backend.KindBranch
	case macho.ARM64_RELOC_PAGE21:
		return backend.KindPage
	case macho.ARM64_RELOC_PAGEOFF12:
		return backend.KindPageOff
	case macho.ARM64_RELOC_GOT_LOAD_PAGE21, macho.ARM64_RELOC_GOT_LOAD_PAGEOFF12:
		return backend.KindGOTLoad
	case macho.ARM64_RELOC_POINTER_TO_GOT:
		return backend.KindGOT
	case macho.ARM64_RELOC_TLVP_LOAD_PAGE21, macho.ARM64_RELOC_TLVP_LOAD_PAGEOFF12:
		return backend.KindTLV
	case macho.ARM64_RELOC_ADDEND:
		return backend.KindAddend
	case macho.ARM64_RELOC_AUTHENTICATED_POINTER:
		return backend.KindAuthPtr
	}
	return backend.KindUnknown
}

// Addend recovers a relocation's addend from the bytes it applies to.
//
// Only UNSIGNED and SUBTRACTOR carry one there. Every other arm64 relocation
// that needs an addend gets it from a preceding ARM64_RELOC_ADDEND entry,
// which link has already folded in by the time an image.Reloc exists — so this
// reports false for them rather than reading an instruction's immediate field
// and mistaking a register number for a displacement.
func (b *Backend) Addend(content []byte, off uint64, r image.Reloc) (int64, bool) {
	switch macho.ARM64Reloc(r.Type) {
	case macho.ARM64_RELOC_UNSIGNED, macho.ARM64_RELOC_SUBTRACTOR:
	default:
		return 0, false
	}
	n := uint64(r.Length.Bytes())
	if off > uint64(len(content)) || n > uint64(len(content))-off {
		return 0, false
	}
	// AArch64 is little-endian in every configuration this tree targets;
	// big-endian Mach-O is readable but is not a target it emits.
	switch r.Length {
	case macho.RelocLong:
		return int64(int32(binary.LittleEndian.Uint32(content[off:]))), true
	case macho.RelocQuad:
		return int64(binary.LittleEndian.Uint64(content[off:])), true
	}
	return 0, false
}

// Scan records what the link must synthesize.
//
// It runs before any address is assigned, so it reads relocations and symbol
// classes and nothing else. Every decision it makes is a count: how many GOT
// slots, how many stubs, how many fixups.
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
	switch kind {
	case backend.KindUnknown:
		return fmt.Errorf("%w: r_type %d at %s+0x%x",
			backend.ErrUnsupportedReloc, r.Type, atom, r.Offset)

	case backend.KindAddend:
		// An ADDEND that survived into an image.Reloc means link did not fold
		// it into its partner. Applying it would write nothing and the partner
		// would then be relocated without its addend, which is a silently
		// wrong address rather than a visible failure.
		return fmt.Errorf("%w: ARM64_RELOC_ADDEND at %s+0x%x was not folded into its partner",
			backend.ErrUnsupportedReloc, atom, r.Offset)
	}

	if kind.NeedsGOT() {
		if r.Sym == nil {
			return fmt.Errorf("arm64: GOT relocation at %s+0x%x names no symbol", atom, r.Offset)
		}
		reqs.GOT(r.Sym)
		return nil
	}
	if kind.NeedsTLV() {
		// Only an imported thread-local needs a pointer slot. One
		// defined here has a descriptor at a known address, so the
		// ADRP/LDR pair is relaxed into ADRP/ADD and addresses it
		// directly — which is what Apple's linker emits, and why a
		// program with thread-locals of its own has no __thread_ptrs
		// section at all.
		//
		// A relocation naming an atom rather than a symbol is one of
		// those: a reference to a local becomes an atom reference when
		// the objects are merged, and a `static _Thread_local` is
		// local. It names nothing that could be imported.
		if tlvIsLocal(r) {
			return nil
		}
		if r.Sym == nil {
			return fmt.Errorf("arm64: TLV relocation at %s+0x%x names neither a symbol nor an atom",
				atom, r.Offset)
		}
		reqs.TLV(r.Sym)
		return nil
	}
	if kind.IsBranch() {
		// A branch immediate cannot be a bind site — there is nowhere for dyld
		// to write an address — so a call to an import goes through a stub.
		// A call to something defined here needs no stub, only possibly a
		// thunk, which is a layout question and not one Scan can answer.
		if r.Sym != nil && r.Sym.Class == image.ClassImport {
			reqs.Stub(r.Sym)
		}
		return nil
	}
	if !kind.IsPointer() {
		return nil
	}

	// A difference between two addresses in this image is a link-time
	// constant. It does not slide, so it is neither a rebase nor a bind.
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
	if int(r.Length.Bytes()) != b.cfg.WordSize {
		return fmt.Errorf("arm64: %d-byte absolute relocation at %s+0x%x cannot be a fixup in a %d-byte-pointer image",
			r.Length.Bytes(), atom, r.Offset, b.cfg.WordSize)
	}

	var auth *backend.PtrAuth
	if pa, ok := b.PtrAuth(r); ok {
		auth = &pa
	}
	if r.Sym != nil && !r.Sym.Defined() {
		return reqs.AddBind(backend.Bind{
			Atom:   atom,
			Offset: r.Offset,
			Sym:    r.Sym,
			Addend: r.Addend,
			Weak:   r.Sym.WeakRef,
			Auth:   auth,
		})
	}
	return reqs.AddRebase(backend.Rebase{Atom: atom, Offset: r.Offset, Auth: auth})
}

// Apply writes one relocation.
func (b *Backend) Apply(s *backend.Site, r image.Reloc) error {
	kind := b.Classify(r.Type)
	if !kind.WritesField() {
		return nil
	}
	pc := s.PC(r.Offset)

	value, err := b.value(s, r, kind)
	if err != nil {
		return err
	}

	base, err := s.Read32(r.Offset)
	if err != nil {
		return err
	}

	switch kind {
	case backend.KindAbsolute, backend.KindAuthPtr:
		// A four-byte UNSIGNED is a field, not a pointer: the second half
		// of a SUBTRACTOR pair, whose difference is a relative pointer
		// into the same image. Writing it as a pointer puts eight bytes
		// where there are four.
		if r.Length == macho.RelocLong {
			if r.Sub != nil {
				if d := int64(value); d < -1<<31 || d >= 1<<31 {
					return b.rangeErr(s, r, d, 32, 0, pc)
				}
			} else if value > 0xffffffff {
				return b.rangeErr(s, r, int64(value), 32, 0, pc)
			}
			return s.Write32(r.Offset, uint32(value))
		}
		// An authenticated pointer's on-disk value is the unsigned target;
		// the key and discriminator travel in the chained-fixup entry, which
		// the fixup encoder writes. Nothing extra happens here.
		return s.WritePointer(r.Offset, value, b.name(r))

	case backend.KindBranch:
		delta := int64(value) - int64(pc)
		if !b.thunk.InRange(pc, value) {
			return b.rangeErr(s, r, delta, 26, 2, pc)
		}
		insn, err := encodeBranch26(base, delta)
		if err != nil {
			return b.decorate(s, r, err, pc)
		}
		return s.Write32(r.Offset, insn)

	case backend.KindPage, backend.KindGOTLoad, backend.KindTLV:
		// PAGE21 and PAGEOFF12 share a Kind with their GOT and TLV variants,
		// so the r_type decides which half this is.
		if isPageOff(r.Type) {
			// The low half of a TLV pair whose descriptor is in this
			// image loads nothing: value is the descriptor's own
			// address, so the LDR becomes an ADD of it. Leaving the LDR
			// would dereference the descriptor and call whatever its
			// first word happens to hold.
			if kind == backend.KindTLV && tlvIsLocal(r) {
				add, err := relaxGotLoadToAdd(base)
				if err != nil {
					return b.decorate(s, r, err, pc)
				}
				insn, err := encodePageOff12(add, value)
				if err != nil {
					return b.decorate(s, r, err, pc)
				}
				return s.Write32(r.Offset, insn)
			}
			insn, err := encodePageOff12(base, value)
			if err != nil {
				return b.decorate(s, r, err, pc)
			}
			return s.Write32(r.Offset, insn)
		}
		delta := int64(pageOf(value)) - int64(pageOf(pc))
		insn, err := encodePage21(base, delta)
		if err != nil {
			return b.decorate(s, r, err, pc)
		}
		return s.Write32(r.Offset, insn)

	case backend.KindPageOff:
		insn, err := encodePageOff12(base, value)
		if err != nil {
			return b.decorate(s, r, err, pc)
		}
		return s.Write32(r.Offset, insn)

	case backend.KindGOT:
		// POINTER_TO_GOT takes the address of the slot. ld64 also has an
		// 8-byte absolute form whose semantics are that the slot's *contents*
		// get written rather than its address; that form is not supported
		// here, and lld does not support it either for want of a real use.
		if !r.PCRel {
			return fmt.Errorf("%w: absolute ARM64_RELOC_POINTER_TO_GOT at %s+0x%x",
				backend.ErrUnsupportedReloc, s.Atom, r.Offset)
		}
		d := int64(value) - int64(pc)
		if err := s.CheckSigned(b.name(r), r.Offset, d, 32, 0); err != nil {
			return err
		}
		return s.Write32(r.Offset, uint32(int32(d)))
	}
	return fmt.Errorf("%w: %v at %s+0x%x",
		backend.ErrUnsupportedReloc, macho.ARM64Reloc(r.Type), s.Atom, r.Offset)
}

// value resolves the address a relocation refers to.
//
// For most kinds that is the symbol or atom the relocation names. For a GOT or
// TLV kind it is the slot's address instead — the instruction loads through
// the table, not from the symbol — which is why this cannot be
// image.Reloc.Target alone.
func (b *Backend) value(s *backend.Site, r image.Reloc, kind backend.Kind) (uint64, error) {
	switch {
	case kind.NeedsGOT():
		return b.slotAddr(s, r.Sym, b.got.Name, b.got.EntrySize, s.Reqs.GOTIndex, "GOT")
	case kind.NeedsTLV():
		// A descriptor defined here is addressed directly; see Scan.
		if tlvIsLocal(r) {
			return r.Target()
		}
		return b.slotAddr(s, r.Sym, macho.Sec(macho.SEG_DATA, macho.SECT_THREAD_PTRS),
			uint32(b.cfg.WordSize), s.Reqs.TLVIndex, "thread-local")
	}

	// A branch to an import goes to that symbol's stub rather than to the
	// symbol, which has no address in this image.
	if kind.IsBranch() && r.Sym != nil && r.Sym.Class == image.ClassImport {
		i, ok := s.Reqs.StubIndex(r.Sym)
		if !ok {
			return 0, fmt.Errorf("arm64: %s is imported and branched to but has no stub", r.Sym.Name)
		}
		base, ok := s.SectionAddr(b.stub.Name)
		if !ok {
			return 0, fmt.Errorf("arm64: the image has no %s section", b.stub.Name)
		}
		return b.stub.Entry(base, i), nil
	}

	// A thread-local descriptor's offset field holds the template's
	// distance from the region base, which is a link-time constant and
	// not the address the relocation appears to name.
	if off, ok := backend.TLVTemplateOffset(s.Img, s.Atom, r); ok {
		return off, nil
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

	v, err := r.Target()
	if err != nil {
		return 0, err
	}
	if r.Sub != nil {
		if !r.Sub.Bound {
			return 0, fmt.Errorf("arm64: subtrahend %s is unbound", r.Sub.Name)
		}
		v -= r.Sub.Value
	}
	return v, nil
}

func (b *Backend) slotAddr(s *backend.Site, sym *image.Sym, name macho.SecName,
	entry uint32, index func(*image.Sym) (int, bool), what string) (uint64, error) {

	if sym == nil {
		return 0, fmt.Errorf("arm64: %s relocation names no symbol", what)
	}
	i, ok := index(sym)
	if !ok {
		return 0, fmt.Errorf("arm64: %s has no %s slot; Scan did not reserve one", sym.Name, what)
	}
	base, ok := s.SectionAddr(name)
	if !ok {
		return 0, fmt.Errorf("arm64: the image has no %s section", name)
	}
	return base + uint64(i)*uint64(entry), nil
}

func (b *Backend) name(r image.Reloc) string { return macho.ARM64Reloc(r.Type).String() }

// decorate fills in the atom and address on a RangeError raised by an encoder,
// which has no way to know either.
func (b *Backend) decorate(s *backend.Site, r image.Reloc, err error, pc uint64) error {
	re, ok := err.(*backend.RangeError)
	if !ok {
		return err
	}
	re.Reloc = b.name(r)
	re.Addr = pc
	if s.Atom != nil {
		re.Atom = s.Atom.String()
		if s.Atom.Input != nil {
			re.Input = s.Atom.Input.Name
		}
	}
	return re
}

func (b *Backend) rangeErr(s *backend.Site, r image.Reloc, v int64, bits, shift int, pc uint64) error {
	return b.decorate(s, r, &backend.RangeError{
		Value: v, Bits: bits, Signed: true, Shift: shift,
	}, pc)
}

// tlvIsLocal reports whether a thread-local relocation names a
// descriptor in this image, which is the case that needs no pointer slot
// and gets the ADRP/ADD form.
//
// An atom reference is always one: merging turns a reference to a local
// symbol into a reference to the atom that defines it, and nothing
// outside the image has an atom here.
func tlvIsLocal(r image.Reloc) bool {
	if r.Atom != nil {
		return true
	}
	return r.Sym != nil && r.Sym.Defined()
}

// isPageOff reports whether an r_type is the low-bits half of a two-instruction
// address materialization.
func isPageOff(typ uint8) bool {
	switch macho.ARM64Reloc(typ) {
	case macho.ARM64_RELOC_PAGEOFF12,
		macho.ARM64_RELOC_GOT_LOAD_PAGEOFF12,
		macho.ARM64_RELOC_TLVP_LOAD_PAGEOFF12:
		return true
	}
	return false
}