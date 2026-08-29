package backend_test

import (
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
)

func sym(name string) *image.Sym { return &image.Sym{Name: name} }

func TestReqsSlotAssignment(t *testing.T) {
	r := backend.NewReqs()
	a, b := sym("_a"), sym("_b")

	i0 := r.GOT(a)
	i1 := r.GOT(b)
	if i0 == i1 {
		t.Fatalf("two distinct symbols got the same GOT slot: %d", i0)
	}
	// Requesting a slot for a symbol already holding one is idempotent.
	if again := r.GOT(a); again != i0 {
		t.Errorf("GOT(a) a second time = %d, want %d (idempotent)", again, i0)
	}
	if idx, ok := r.GOTIndex(a); !ok || idx != i0 {
		t.Errorf("GOTIndex(a) = %d,%v, want %d,true", idx, ok, i0)
	}
	if _, ok := r.GOTIndex(sym("_never_added")); ok {
		t.Error("GOTIndex on a symbol never given a slot returned ok=true")
	}
	if r.GOTCount() != 2 {
		t.Errorf("GOTCount() = %d, want 2", r.GOTCount())
	}
	syms := r.GOTSyms()
	if len(syms) != 2 || syms[0] != a || syms[1] != b {
		t.Errorf("GOTSyms() = %v, want [a, b] in assignment order", syms)
	}

	// Stub and TLV slots are independent namespaces from GOT and from each
	// other, even for the same symbol.
	sIdx := r.Stub(a)
	tIdx := r.TLV(a)
	if sIdx != 0 {
		t.Errorf("Stub(a) = %d, want 0 (its own namespace)", sIdx)
	}
	if tIdx != 0 {
		t.Errorf("TLV(a) = %d, want 0 (its own namespace)", tIdx)
	}
}

func TestReqsRebaseAndBind(t *testing.T) {
	r := backend.NewReqs()
	atom := &image.Atom{Name: "<test>"}
	defined := sym("_defined")
	defined.Class = image.ClassDefined
	imported := sym("_imported")
	imported.Class = image.ClassImport

	if err := r.AddRebase(backend.Rebase{Atom: atom, Offset: 0}); err != nil {
		t.Fatalf("AddRebase: %v", err)
	}
	if err := r.AddRebase(backend.Rebase{Atom: nil}); err == nil {
		t.Error("AddRebase with a nil atom should fail")
	}

	if err := r.AddBind(backend.Bind{Atom: atom, Offset: 8, Sym: imported}); err != nil {
		t.Fatalf("AddBind: %v", err)
	}
	if err := r.AddBind(backend.Bind{Atom: atom, Sym: nil}); err == nil {
		t.Error("AddBind with no symbol should fail")
	}
	if err := r.AddBind(backend.Bind{Atom: atom, Sym: defined}); err == nil {
		t.Error("AddBind against a defined symbol should fail (that is a rebase, not a bind)")
	}

	if got := len(r.Rebases()); got != 1 {
		t.Errorf("len(Rebases()) = %d, want 1", got)
	}
	if got := len(r.Binds()); got != 1 {
		t.Errorf("len(Binds()) = %d, want 1", got)
	}
	if r.Fixups() != 2 {
		t.Errorf("Fixups() = %d, want 2", r.Fixups())
	}
	if r.Empty() {
		t.Error("Empty() = true, want false: rebases/binds/GOT slots exist")
	}
	if backend.NewReqs().Empty() != true {
		t.Error("a fresh Reqs should report Empty() = true")
	}
}

func TestReqsHints(t *testing.T) {
	r := backend.NewReqs()
	if got := r.Hints(); got != nil {
		t.Errorf("Hints() on a fresh Reqs = %v, want nil", got)
	}
	hints := []backend.Hint{{Kind: 1}}
	r.SetHints(hints)
	if got := r.Hints(); len(got) != 1 {
		t.Errorf("Hints() after SetHints = %v, want 1 entry", got)
	}
}

func TestGotShapeMath(t *testing.T) {
	g := backend.GotShape{
		Name:      macho.Sec(macho.SEG_DATA_CONST, macho.SECT_GOT),
		Type:      macho.S_NON_LAZY_SYMBOL_POINTERS,
		EntrySize: 8,
		Align:     8,
	}
	if err := g.Valid(); err != nil {
		t.Fatalf("Valid: %v", err)
	}
	if got := g.Slot(0x1000, 3); got != 0x1000+24 {
		t.Errorf("Slot(0x1000, 3) = %#x, want %#x", got, 0x1000+24)
	}
	if got := g.Size(5); got != 40 {
		t.Errorf("Size(5) = %d, want 40", got)
	}

	bad := g
	bad.EntrySize = 0
	if bad.Valid() == nil {
		t.Error("Valid() accepted a zero entry size")
	}
	bad = g
	bad.Type = macho.S_REGULAR
	if bad.Valid() == nil {
		t.Error("Valid() accepted a non-indirect section type")
	}
	bad = g
	bad.Align = 3
	if bad.Valid() == nil {
		t.Error("Valid() accepted a non-power-of-two alignment")
	}
}

func TestStubShapeMath(t *testing.T) {
	s := backend.StubShape{
		Kind:      backend.StubNonLazy,
		Name:      macho.Sec(macho.SEG_TEXT, macho.SECT_STUBS),
		Type:      macho.S_SYMBOL_STUBS,
		EntrySize: 12,
		Align:     4,
	}
	if err := s.Valid(); err != nil {
		t.Fatalf("Valid: %v", err)
	}
	if got := s.Entry(0x2000, 2); got != 0x2000+24 {
		t.Errorf("Entry(0x2000, 2) = %#x, want %#x", got, 0x2000+24)
	}
	if got := s.Size(3); got != 36 {
		t.Errorf("Size(3) = %d, want 36", got)
	}
	// Non-lazy: no helper, so HelperSize is always zero.
	if got := s.HelperSize(5); got != 0 {
		t.Errorf("HelperSize on a non-lazy shape = %d, want 0", got)
	}

	lazy := backend.StubShape{
		Kind:             backend.StubLazy,
		Name:             macho.Sec(macho.SEG_TEXT, macho.SECT_STUBS),
		Type:             macho.S_SYMBOL_STUBS,
		EntrySize:        12,
		Align:            4,
		PointerName:      macho.Sec(macho.SEG_DATA, macho.SECT_LA_SYMBOL_PTR),
		PointerType:      macho.S_LAZY_SYMBOL_POINTERS,
		HelperName:       macho.Sec(macho.SEG_TEXT, macho.SECT_STUB_HELPER),
		HelperHeaderSize: 24,
		HelperEntrySize:  12,
	}
	if err := lazy.Valid(); err != nil {
		t.Fatalf("lazy Valid: %v", err)
	}
	if got := lazy.HelperSize(2); got != 24+2*12 {
		t.Errorf("HelperSize(2) = %d, want %d", got, 24+2*12)
	}
	if got := lazy.HelperEntry(0x3000, 1); got != 0x3000+24+12 {
		t.Errorf("HelperEntry(0x3000, 1) = %#x, want %#x", got, 0x3000+24+12)
	}

	badLazy := lazy
	badLazy.PointerType = macho.S_REGULAR
	if badLazy.Valid() == nil {
		t.Error("Valid() accepted a lazy shape whose pointer section has the wrong type")
	}
	badLazy = lazy
	badLazy.HelperHeaderSize = 0
	if badLazy.Valid() == nil {
		t.Error("Valid() accepted a lazy shape with a zero helper header size")
	}
}

// TestThunkShapeAsymmetricReach checks the asymmetry the doc comment
// describes: a two's-complement branch immediate reaches one instruction
// further backward than forward.
func TestThunkShapeAsymmetricReach(t *testing.T) {
	const (
		instrSize = 4
		imm26     = 1 << 26
	)
	forward := int64(imm26/2-1) * instrSize
	backward := int64(imm26/2) * instrSize
	ts := backend.ThunkShape{Size: 12, Align: 4, Forward: forward, Backward: backward}
	if err := ts.Valid(); err != nil {
		t.Fatalf("Valid: %v", err)
	}

	from := uint64(1 << 32)
	if !ts.InRange(from, from+uint64(forward)) {
		t.Error("a branch to exactly +Forward should be in range")
	}
	if ts.InRange(from, from+uint64(forward)+instrSize) {
		t.Error("a branch past +Forward should be out of range")
	}
	if !ts.InRange(from, from-uint64(backward)) {
		t.Error("a branch to exactly -Backward should be in range")
	}
	if ts.InRange(from, from-uint64(backward)-instrSize) {
		t.Error("a branch past -Backward should be out of range")
	}
	// The asymmetry itself: one instruction beyond Forward would still be
	// within Backward's magnitude, so the two bounds must differ.
	if forward == backward {
		t.Fatal("test setup error: forward and backward reach should differ")
	}
}

func TestPtrAuthKeyCode(t *testing.T) {
	if !backend.PtrAuthIA.Code() || !backend.PtrAuthIB.Code() {
		t.Error("instruction keys should report Code() = true")
	}
	if backend.PtrAuthDA.Code() || backend.PtrAuthDB.Code() {
		t.Error("data keys should report Code() = false")
	}
}
