package backend

import (
	"fmt"

	"github.com/vertex-language/macho/image"
)

// Reqs is what a link needs synthesized, accumulated by Backend.Scan and read
// by the synthetic-section generators.
//
// It is per-link state, held by the Linker rather than by the Backend, which
// is what lets one registered backend serve concurrent links.
//
// # Why slots are indices and not addresses
//
// Scan runs in the open phase, before __PAGEZERO is sized or __TEXT is placed.
// Nothing has an address yet. What Scan can decide is how many slots exist and
// which symbol owns each one, and that is enough to size the sections that
// layout then places. The address of slot i is computed from the section's
// assigned base and the shape's entry size, at the point of use, rather than
// stored — the same rule the rest of the tree applies to widths.
//
// # Ordering
//
// Slot indices are assignment order, which is Scan's walk order over live
// atoms and their relocations. That is deterministic given the same inputs and
// the same ordering pass, and it has to be: the indirect symbol table is
// indexed by slot number, so two runs that assign slots differently produce
// two different files from one set of objects.
type Reqs struct {
	got   slots
	stubs slots
	tlv   slots

	rebases []Rebase
	binds   []Bind
}

// NewReqs returns an empty Reqs.
func NewReqs() *Reqs { return &Reqs{} }

// slots is an insertion-ordered set of symbols.
type slots struct {
	index map[*image.Sym]int
	syms  []*image.Sym
}

// add returns the symbol's slot, assigning one if it has none. It is
// idempotent, which is what lets Scan call it once per relocation without
// deduplicating first — a symbol referenced from a hundred call sites gets one
// slot.
func (s *slots) add(sym *image.Sym) int {
	if s.index == nil {
		s.index = make(map[*image.Sym]int)
	}
	if i, ok := s.index[sym]; ok {
		return i
	}
	i := len(s.syms)
	s.index[sym] = i
	s.syms = append(s.syms, sym)
	return i
}

func (s *slots) get(sym *image.Sym) (int, bool) {
	i, ok := s.index[sym]
	return i, ok
}

// GOT reserves a global offset table slot for sym and returns its index.
func (r *Reqs) GOT(sym *image.Sym) int { return r.got.add(sym) }

// GOTIndex returns sym's GOT slot, and false if it has none.
func (r *Reqs) GOTIndex(sym *image.Sym) (int, bool) { return r.got.get(sym) }

// GOTSyms returns the symbols with GOT slots, in slot order. The indirect
// symbol table for the GOT section is built by walking this.
func (r *Reqs) GOTSyms() []*image.Sym { return r.got.syms }

// GOTCount returns the number of GOT slots.
func (r *Reqs) GOTCount() int { return len(r.got.syms) }

// Stub reserves a stub for sym and returns its index.
//
// A stub is needed when a branch targets a symbol whose address is not known
// at link time — an import — because a branch immediate cannot be a bind site.
// A branch to a symbol defined in this image needs no stub, only possibly a
// thunk.
func (r *Reqs) Stub(sym *image.Sym) int { return r.stubs.add(sym) }

// StubIndex returns sym's stub, and false if it has none.
func (r *Reqs) StubIndex(sym *image.Sym) (int, bool) { return r.stubs.get(sym) }

// StubSyms returns the symbols with stubs, in stub order.
func (r *Reqs) StubSyms() []*image.Sym { return r.stubs.syms }

// StubCount returns the number of stubs.
func (r *Reqs) StubCount() int { return len(r.stubs.syms) }

// TLV reserves a thread-local variable slot for sym and returns its index.
func (r *Reqs) TLV(sym *image.Sym) int { return r.tlv.add(sym) }

// TLVIndex returns sym's TLV slot, and false if it has none.
func (r *Reqs) TLVIndex(sym *image.Sym) (int, bool) { return r.tlv.get(sym) }

// TLVSyms returns the symbols with TLV slots, in slot order.
func (r *Reqs) TLVSyms() []*image.Sym { return r.tlv.syms }

// TLVCount returns the number of TLV slots.
func (r *Reqs) TLVCount() int { return len(r.tlv.syms) }

// Rebase is a pointer in the image that holds an address within the image and
// must be adjusted when dyld slides it.
//
// Every absolute pointer to something in this image is one of these. They are
// the bulk of a typical image's fixups and the reason chained fixups exist:
// under the classic opcode stream each rebase costs bytes in __LINKEDIT, while
// a chain threads them through the pointers themselves and costs nothing.
type Rebase struct {
	Atom   *image.Atom
	Offset uint64 // from the start of the atom

	// Auth is the signing schema when the pointer is an arm64e signed
	// pointer, and nil otherwise. A signed rebase is still a rebase — the
	// target is in this image — but the entry that encodes it has a different
	// shape.
	Auth *PtrAuth
}

// Bind is a pointer that holds an address in another image, resolved by dyld
// at load time from a symbol name and a library ordinal.
type Bind struct {
	Atom   *image.Atom
	Offset uint64

	Sym *image.Sym

	// Addend is added to the resolved address. The chained-fixup encodings
	// carry a small addend inline and spill larger ones, which is a concern
	// for the encoder rather than for this record.
	Addend int64

	// Weak marks a bind that may fail: the symbol is allowed not to exist, and
	// the pointer binds to zero if it does not.
	Weak bool

	// Auth is the arm64e signing schema, or nil.
	Auth *PtrAuth
}

// AddRebase records a slide-sensitive pointer.
func (r *Reqs) AddRebase(b Rebase) error {
	if b.Atom == nil {
		return fmt.Errorf("backend: rebase with no atom")
	}
	r.rebases = append(r.rebases, b)
	return nil
}

// AddBind records a pointer dyld must resolve.
//
// The symbol must be one the link will emit as an import; binding to a symbol
// defined in this image is a rebase, and recording it as a bind produces an
// image that asks dyld to look up a name it already contains.
func (r *Reqs) AddBind(b Bind) error {
	if b.Atom == nil {
		return fmt.Errorf("backend: bind with no atom")
	}
	if b.Sym == nil {
		return fmt.Errorf("backend: bind at %s+0x%x names no symbol", b.Atom, b.Offset)
	}
	if b.Sym.Defined() {
		return fmt.Errorf("backend: %s is defined in this image; that is a rebase, not a bind",
			b.Sym.Name)
	}
	r.binds = append(r.binds, b)
	return nil
}

// Rebases returns the recorded rebase sites in the order they were added.
func (r *Reqs) Rebases() []Rebase { return r.rebases }

// Binds returns the recorded bind sites in the order they were added.
func (r *Reqs) Binds() []Bind { return r.binds }

// Fixups returns the total number of runtime fixups, which is what decides
// whether an image needs a fixup stream at all.
func (r *Reqs) Fixups() int { return len(r.rebases) + len(r.binds) }

// Empty reports whether the link needs nothing synthesized. A static-content
// executable with no imports is the case that reaches here.
func (r *Reqs) Empty() bool {
	return r.GOTCount() == 0 && r.StubCount() == 0 && r.TLVCount() == 0 && r.Fixups() == 0
}

func (r *Reqs) String() string {
	return fmt.Sprintf("%d got, %d stubs, %d tlv, %d rebases, %d binds",
		r.GOTCount(), r.StubCount(), r.TLVCount(), len(r.rebases), len(r.binds))
}