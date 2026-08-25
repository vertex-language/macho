package backend

import (
	"fmt"

	"github.com/vertex-language/macho"
)

// GotShape describes the global offset table this architecture wants.
//
// The GOT is one entry per imported or address-taken symbol, and its section
// identity matters as much as its size: a slot in __DATA_CONST is made
// read-only after dyld applies fixups, which is most of the point of having
// __DATA_CONST at all. A backend that places the GOT in __DATA gives up that
// hardening silently.
type GotShape struct {
	// Name is the (segment, section) identity of the GOT.
	Name macho.SecName

	// Type is the section type. It must be S_NON_LAZY_SYMBOL_POINTERS, which
	// is what makes the section indirect — its reserved1 indexes the shared
	// indirect symbol table, one entry per slot.
	Type macho.SecType

	Attrs macho.SecAttrs

	// EntrySize is the size of one slot in bytes, which is the pointer width.
	EntrySize uint32

	// Align is the section's alignment in bytes. Slots must be naturally
	// aligned or a chained-fixup chain cannot walk them at its declared
	// stride.
	Align uint32
}

// Valid reports whether the shape is internally consistent and expressible.
func (g GotShape) Valid() error {
	if !g.Name.Valid() {
		return fmt.Errorf("backend: GOT section name %s does not fit its fields", g.Name)
	}
	if !g.Type.Indirect() {
		return fmt.Errorf("backend: GOT section %s has type %v, which has no indirect symbol entries",
			g.Name, g.Type)
	}
	if g.EntrySize == 0 || g.Align == 0 || g.Align&(g.Align-1) != 0 {
		return fmt.Errorf("backend: GOT entry size %d, alignment %d is not a power of two",
			g.EntrySize, g.Align)
	}
	return nil
}

// Slot returns the address of GOT slot i given the section's base address.
func (g GotShape) Slot(base uint64, i int) uint64 {
	return base + uint64(i)*uint64(g.EntrySize)
}

// Size returns the byte size of a GOT holding n slots.
func (g GotShape) Size(n int) uint64 { return uint64(n) * uint64(g.EntrySize) }

// StubShape describes this architecture's stubs.
//
// EntrySize is the value that goes in the stub section's reserved2 field, and
// it is the reason a stub section is special: reserved1 says where the
// section's indirect symbol entries begin and reserved2 says how large one
// stub is, so a tool can divide the section into entries and pair each with a
// symbol. Getting reserved2 wrong misattributes every stub in the image.
type StubShape struct {
	Kind StubKind

	// Name, Type, and Attrs identify __TEXT,__stubs. Type must be
	// S_SYMBOL_STUBS.
	Name  macho.SecName
	Type  macho.SecType
	Attrs macho.SecAttrs

	// EntrySize is one stub in bytes — 12 on arm64 (adrp, ldr, br), 6 on
	// x86_64 (a rip-relative indirect jmp). This is reserved2.
	EntrySize uint32

	// Align is the stub section's alignment in bytes.
	Align uint32

	// The remaining fields describe lazy binding and are meaningful only when
	// Kind is StubLazy. A StubNonLazy shape leaves them zero, and link never
	// creates the sections they name.

	// PointerName identifies __DATA,__la_symbol_ptr, the slot a lazy stub
	// jumps through. Its type must be S_LAZY_SYMBOL_POINTERS.
	PointerName macho.SecName
	PointerType macho.SecType

	// HelperName identifies __TEXT,__stub_helper.
	HelperName macho.SecName

	// HelperHeaderSize is the one-per-image prologue that calls
	// dyld_stub_binder; HelperEntrySize is the per-symbol trampoline that
	// precedes it. On arm64 these are 24 and 12.
	HelperHeaderSize uint32
	HelperEntrySize  uint32
}

// Valid reports whether the shape is internally consistent.
func (s StubShape) Valid() error {
	if s.Kind == StubNone {
		return nil
	}
	if !s.Name.Valid() {
		return fmt.Errorf("backend: stub section name %s does not fit its fields", s.Name)
	}
	if s.Type != macho.S_SYMBOL_STUBS {
		return fmt.Errorf("backend: stub section %s has type %v, want S_SYMBOL_STUBS",
			s.Name, s.Type)
	}
	if s.EntrySize == 0 {
		return fmt.Errorf("backend: stub section %s declares a zero entry size", s.Name)
	}
	if s.Align == 0 || s.Align&(s.Align-1) != 0 {
		return fmt.Errorf("backend: stub alignment %d is not a power of two", s.Align)
	}
	if s.Kind.Lazy() {
		if !s.PointerName.Valid() || !s.HelperName.Valid() {
			return fmt.Errorf("backend: lazy stubs need both a pointer and a helper section")
		}
		if s.PointerType != macho.S_LAZY_SYMBOL_POINTERS {
			return fmt.Errorf("backend: lazy pointer section %s has type %v, want S_LAZY_SYMBOL_POINTERS",
				s.PointerName, s.PointerType)
		}
		if s.HelperHeaderSize == 0 || s.HelperEntrySize == 0 {
			return fmt.Errorf("backend: lazy stubs need nonzero helper header and entry sizes")
		}
	}
	return nil
}

// Entry returns the address of stub i given the section's base address.
func (s StubShape) Entry(base uint64, i int) uint64 {
	return base + uint64(i)*uint64(s.EntrySize)
}

// Size returns the byte size of a stub section holding n stubs.
func (s StubShape) Size(n int) uint64 { return uint64(n) * uint64(s.EntrySize) }

// HelperSize returns the byte size of __stub_helper for n lazy symbols,
// including the one-per-image header.
func (s StubShape) HelperSize(n int) uint64 {
	if !s.Kind.Lazy() || n == 0 {
		return 0
	}
	return uint64(s.HelperHeaderSize) + uint64(n)*uint64(s.HelperEntrySize)
}

// HelperEntry returns the address of helper entry i, which sits after the
// header.
func (s StubShape) HelperEntry(base uint64, i int) uint64 {
	return base + uint64(s.HelperHeaderSize) + uint64(i)*uint64(s.HelperEntrySize)
}

// ThunkShape describes range-extension thunks.
//
// Forward and backward reach are separate fields and are not the same number.
// A branch immediate is a two's complement field scaled by the instruction
// size, so it reaches one instruction further backwards than forwards: on
// arm64 the 26-bit field scaled by 4 gives exactly 128 MiB backwards and four
// bytes less than that forwards. Using one number for both either wastes
// thunks or, if the larger number is chosen, produces a branch that overflows
// at the far edge — which is a link that succeeds and a program that jumps
// into the wrong function.
type ThunkShape struct {
	// Size is one thunk in bytes.
	Size uint32

	// Align is the thunk's alignment in bytes.
	Align uint32

	// Forward is the largest positive displacement a branch can encode;
	// Backward is the largest magnitude of a negative one. Both are in bytes
	// and both are inclusive.
	Forward  int64
	Backward int64
}

// InRange reports whether a branch at from can reach to directly.
//
// The comparison is done in signed 64-bit arithmetic on the difference rather
// than on the addresses, so an image mapped high does not wrap.
func (t ThunkShape) InRange(from, to uint64) bool {
	d := int64(to) - int64(from)
	if d >= 0 {
		return d <= t.Forward
	}
	return -d <= t.Backward
}

// Valid reports whether the shape is usable.
func (t ThunkShape) Valid() error {
	if t.Size == 0 {
		return fmt.Errorf("backend: thunk shape declares a zero size")
	}
	if t.Align == 0 || t.Align&(t.Align-1) != 0 {
		return fmt.Errorf("backend: thunk alignment %d is not a power of two", t.Align)
	}
	if t.Forward <= 0 || t.Backward <= 0 {
		return fmt.Errorf("backend: thunk reach must be positive in both directions, got +%d/-%d",
			t.Forward, t.Backward)
	}
	return nil
}

// PtrAuth is an arm64e pointer-authentication schema.
//
// A signed pointer is not stored as an address. What lands on disk is a
// chained-fixup entry carrying these four values, and the runtime computes the
// signature from them — so this travels beside the pointer rather than inside
// it, and a linker that writes an address where a signed pointer belongs
// produces an image that faults on first use.
type PtrAuth struct {
	// Key selects the signing key: instruction keys A and B for code
	// pointers, data keys A and B for data.
	Key PtrAuthKey

	// Diversity is a 16-bit constant mixed into the discriminator, usually a
	// hash of the pointer's declared type.
	Diversity uint16

	// AddrDiv mixes the pointer's own storage address into the discriminator,
	// so a signed pointer copied elsewhere no longer authenticates. It is what
	// makes a signed vtable slot useless to an attacker who can move it.
	AddrDiv bool
}

// PtrAuthKey is the key a signed pointer is signed with.
type PtrAuthKey uint8

const (
	PtrAuthIA PtrAuthKey = 0 // instruction key A
	PtrAuthIB PtrAuthKey = 1 // instruction key B
	PtrAuthDA PtrAuthKey = 2 // data key A
	PtrAuthDB PtrAuthKey = 3 // data key B
)

func (k PtrAuthKey) String() string {
	switch k {
	case PtrAuthIA:
		return "IA"
	case PtrAuthIB:
		return "IB"
	case PtrAuthDA:
		return "DA"
	case PtrAuthDB:
		return "DB"
	}
	return "key(?)"
}

// Code reports whether this key signs a code pointer.
func (k PtrAuthKey) Code() bool { return k == PtrAuthIA || k == PtrAuthIB }