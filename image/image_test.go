package image_test

import (
	"errors"
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/image"
)

func target(t *testing.T) macho.Target {
	t.Helper()
	tgt, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tgt
}

func TestPhaseOrderIsEnforced(t *testing.T) {
	img := image.New(target(t))

	// Operations that need PhaseSealed must fail in PhaseOpen.
	seg, err := img.Segment(macho.SEG_TEXT)
	if err != nil {
		t.Fatalf("Segment: %v", err)
	}
	if err := seg.SetPlacement(0, 0, 0, 0); !errors.Is(err, image.ErrPhase) {
		t.Errorf("SetPlacement before Seal: err = %v, want ErrPhase", err)
	}
	if err := img.WriteAt(0, []byte{1}); !errors.Is(err, image.ErrNotFrozen) {
		t.Errorf("WriteAt before Freeze: err = %v, want ErrNotFrozen", err)
	}
	if _, err := img.Bytes(); !errors.Is(err, image.ErrNotFrozen) {
		t.Errorf("Bytes before Freeze: err = %v, want ErrNotFrozen", err)
	}

	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Operations that need PhaseOpen must fail once sealed.
	if _, err := img.Segment(macho.SEG_DATA); !errors.Is(err, image.ErrPhase) {
		t.Errorf("Segment after Seal: err = %v, want ErrPhase", err)
	}
	if err := img.Seal(); !errors.Is(err, image.ErrPhase) {
		t.Errorf("Seal twice: err = %v, want ErrPhase", err)
	}

	if err := seg.SetPlacement(0, 0x4000, 0, 0x4000); err != nil {
		t.Fatalf("SetPlacement: %v", err)
	}
	if err := img.SetSize(0x4000); err != nil {
		t.Fatalf("SetSize: %v", err)
	}
	if err := img.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	// And PhaseSealed operations must fail once frozen.
	if err := img.SetSize(1); !errors.Is(err, image.ErrPhase) {
		t.Errorf("SetSize after Freeze: err = %v, want ErrPhase", err)
	}
	if err := img.WriteAt(0, []byte{1, 2, 3}); err != nil {
		t.Errorf("WriteAt after Freeze: %v", err)
	}
}

func TestWriteAtBoundsChecking(t *testing.T) {
	img := image.New(target(t))
	seg, err := img.Segment(macho.SEG_TEXT)
	if err != nil {
		t.Fatalf("Segment: %v", err)
	}
	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := seg.SetPlacement(0, 0x1000, 0, 0x1000); err != nil {
		t.Fatalf("SetPlacement: %v", err)
	}
	if err := img.SetSize(0x1000); err != nil {
		t.Fatalf("SetSize: %v", err)
	}
	if err := img.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	if err := img.WriteAt(0x1000-4, []byte{1, 2, 3, 4}); err != nil {
		t.Errorf("write exactly at the end: %v", err)
	}
	if err := img.WriteAt(0x1000-3, []byte{1, 2, 3, 4}); !errors.Is(err, image.ErrOutOfBounds) {
		t.Errorf("write past the end: err = %v, want ErrOutOfBounds", err)
	}
	if _, err := img.Slice(0x1000, 1); !errors.Is(err, image.ErrOutOfBounds) {
		t.Errorf("Slice past the end: err = %v, want ErrOutOfBounds", err)
	}
}

// TestSegmentOrderingIsCanonical checks that Seal reorders segments into the
// canonical layout (__PAGEZERO first, __LINKEDIT last) regardless of the
// order they were created in.
func TestSegmentOrderingIsCanonical(t *testing.T) {
	img := image.New(target(t))
	// Deliberately scrambled creation order.
	for _, name := range []string{macho.SEG_LINKEDIT, macho.SEG_DATA, macho.SEG_TEXT, macho.SEG_PAGEZERO} {
		if _, err := img.Segment(name); err != nil {
			t.Fatalf("Segment(%s): %v", name, err)
		}
	}
	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	segs := img.Segments()
	if len(segs) != 4 {
		t.Fatalf("got %d segments, want 4", len(segs))
	}
	if segs[0].Name != macho.SEG_PAGEZERO {
		t.Errorf("segs[0] = %s, want %s", segs[0].Name, macho.SEG_PAGEZERO)
	}
	if segs[len(segs)-1].Name != macho.SEG_LINKEDIT {
		t.Errorf("segs[last] = %s, want %s", segs[len(segs)-1].Name, macho.SEG_LINKEDIT)
	}
	if segs[1].Name != macho.SEG_TEXT {
		t.Errorf("segs[1] = %s, want %s (right after __PAGEZERO)", segs[1].Name, macho.SEG_TEXT)
	}
}

// TestFreezeRejectsOverlappingSections checks that Freeze's layout validation
// actually catches two sections in one segment claiming the same address
// range — the specific kind of mistake the phase model exists to catch rather
// than let through as a file that parses and then misbehaves.
func TestFreezeRejectsOverlappingSections(t *testing.T) {
	img := image.New(target(t))
	a, err := img.Section(image.SectionKey{
		Name: macho.Sec(macho.SEG_TEXT, macho.SECT_TEXT), Type: macho.S_REGULAR,
	})
	if err != nil {
		t.Fatalf("Section a: %v", err)
	}
	b, err := img.Section(image.SectionKey{
		Name: macho.Sec(macho.SEG_TEXT, macho.SECT_CSTRING), Type: macho.S_CSTRING_LITERALS,
	})
	if err != nil {
		t.Fatalf("Section b: %v", err)
	}
	seg := a.Segment()

	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// b starts before a ends: a genuine overlap.
	if err := a.SetPlacement(0, 16, 0); err != nil {
		t.Fatalf("SetPlacement a: %v", err)
	}
	if err := b.SetPlacement(8, 16, 8); err != nil {
		t.Fatalf("SetPlacement b: %v", err)
	}
	if err := seg.SetPlacement(0, 0x1000, 0, 0x1000); err != nil {
		t.Fatalf("SetPlacement seg: %v", err)
	}
	if err := img.SetSize(0x1000); err != nil {
		t.Fatalf("SetSize: %v", err)
	}

	if err := img.Freeze(); !errors.Is(err, image.ErrLayout) {
		t.Errorf("Freeze on overlapping sections: err = %v, want ErrLayout", err)
	}
}

// TestFreezeRejectsContentAfterZerofill checks the other layout invariant
// validate enforces: a zerofill section (no file bytes) followed by one that
// has file bytes cannot be described as one contiguous file mapping.
func TestFreezeRejectsContentAfterZerofill(t *testing.T) {
	img := image.New(target(t))
	bss, err := img.Section(image.SectionKey{
		Name: macho.Sec(macho.SEG_DATA, macho.SECT_BSS), Type: macho.S_ZEROFILL,
	})
	if err != nil {
		t.Fatalf("Section bss: %v", err)
	}
	data, err := img.Section(image.SectionKey{
		Name: macho.Sec(macho.SEG_DATA, macho.SECT_DATA), Type: macho.S_REGULAR,
	})
	if err != nil {
		t.Fatalf("Section data: %v", err)
	}
	seg := bss.Segment()

	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := bss.SetPlacement(0, 16, 0); err != nil {
		t.Fatalf("SetPlacement bss: %v", err)
	}
	if err := data.SetPlacement(16, 16, 16); err != nil {
		t.Fatalf("SetPlacement data: %v", err)
	}
	if err := seg.SetPlacement(0, 0x1000, 0, 0x1000); err != nil {
		t.Fatalf("SetPlacement seg: %v", err)
	}
	if err := img.SetSize(0x1000); err != nil {
		t.Fatalf("SetSize: %v", err)
	}

	if err := img.Freeze(); !errors.Is(err, image.ErrLayout) {
		t.Errorf("Freeze with content after zerofill: err = %v, want ErrLayout", err)
	}
}

func TestSymbolTable(t *testing.T) {
	img := image.New(target(t))
	syms := img.Symbols()

	a := syms.Intern("_a")
	a2 := syms.Intern("_a")
	if a != a2 {
		t.Error("Intern of the same name twice returned different symbols")
	}
	if syms.Find("_a") != a {
		t.Error("Find did not return the interned symbol")
	}
	if syms.Find("_nonexistent") != nil {
		t.Error("Find on an unknown name returned non-nil")
	}

	a.Class = image.ClassDefined
	undef := syms.Intern("_undef")
	undef.Class = image.ClassUndefined

	undefs := syms.Undefined()
	found := false
	for _, s := range undefs {
		if s == undef {
			found = true
		}
		if s == a {
			t.Error("Undefined() included a defined symbol")
		}
	}
	if !found {
		t.Error("Undefined() did not include _undef")
	}
}

func TestAddReservedSymbolsAreAbsolute(t *testing.T) {
	img := image.New(target(t))
	if err := img.AddReserved(); err != nil {
		t.Fatalf("AddReserved: %v", err)
	}
	reserved := img.Reserved()
	if len(reserved) == 0 {
		t.Fatal("AddReserved recorded no symbols")
	}
	for _, s := range reserved {
		if s.Class != image.ClassAbsolute {
			t.Errorf("%s: Class = %v, want ClassAbsolute", s.Name, s.Class)
		}
		if !s.Root {
			t.Errorf("%s: Root = false, want true", s.Name)
		}
	}

	dso := img.Symbols().Find("___dso_handle")
	if dso == nil {
		t.Fatal("___dso_handle was not interned")
	}

	if err := img.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// BindReserved needs PhaseSealed and sets every reserved symbol's value
	// to the image's base address.
	if err := img.BindReserved(); err != nil {
		t.Fatalf("BindReserved: %v", err)
	}
	if dso.Value != img.BaseAddress() {
		t.Errorf("___dso_handle.Value = %#x, want base address %#x", dso.Value, img.BaseAddress())
	}
	if !dso.Bound {
		t.Error("___dso_handle.Bound = false after BindReserved")
	}
}
