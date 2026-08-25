package backend

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/image"
)

// Site is one atom's output bytes, with the address they will occupy.
//
// A backend's Apply writes through a Site rather than through the image
// directly, for two reasons. The buffer here is a window onto the real output
// bytes — image.Slice hands back the underlying array — so a backend patches
// the bytes that get written rather than a copy it has to remember to write
// back. And every write goes through a bounds check against the atom, so a
// relocation whose address is past the end of its own atom is an error naming
// the atom and the input, rather than a corrupted neighbour.
//
// A Site is only meaningful after Freeze. SiteFor enforces that by asking the
// image for a slice, which is itself a phase-checked operation.
type Site struct {
	// Buf is the atom's bytes in the output buffer. Writes through it are
	// writes to the image.
	Buf []byte

	// Base is the virtual address of Buf[0].
	Base uint64

	Atom *image.Atom
	Img  *image.Image
	Reqs *Reqs

	ord  binary.ByteOrder
	word int
}

// SiteFor returns a Site over one atom's output bytes.
func SiteFor(img *image.Image, a *image.Atom, reqs *Reqs) (*Site, error) {
	if a == nil {
		return nil, fmt.Errorf("backend: SiteFor(nil atom)")
	}
	if a.Zerofill() {
		return nil, fmt.Errorf("backend: %s is zerofill and has no bytes to relocate", a)
	}
	off, err := a.FileOffset()
	if err != nil {
		return nil, err
	}
	addr, err := a.Addr()
	if err != nil {
		return nil, err
	}
	buf, err := img.Slice(off, a.Size())
	if err != nil {
		return nil, err
	}
	return &Site{
		Buf:  buf,
		Base: addr,
		Atom: a,
		Img:  img,
		Reqs: reqs,
		ord:  img.Endian().Order(),
		word: img.Width().Bits() / 8,
	}, nil
}

// Order returns the byte order the image is written in.
func (s *Site) Order() binary.ByteOrder { return s.ord }

// WordSize returns the image's pointer size in bytes.
func (s *Site) WordSize() int { return s.word }

// PC returns the virtual address of the field at off.
//
// It is named for the use it gets: on every architecture this tree targets, a
// pc-relative relocation measures from the address of the instruction being
// relocated, not from the next one, so this is the value a displacement is
// computed against.
func (s *Site) PC(off uint64) uint64 { return s.Base + off }

// field returns a bounds-checked view of n bytes at off.
func (s *Site) field(off uint64, n int) ([]byte, error) {
	if n < 0 || off > uint64(len(s.Buf)) || uint64(n) > uint64(len(s.Buf))-off {
		return nil, fmt.Errorf("%w: %s writes %d bytes at +0x%x of a %d-byte atom",
			image.ErrOutOfBounds, s.where(), n, off, len(s.Buf))
	}
	return s.Buf[off : off+uint64(n)], nil
}

// Read32 reads a 32-bit field.
func (s *Site) Read32(off uint64) (uint32, error) {
	b, err := s.field(off, 4)
	if err != nil {
		return 0, err
	}
	return s.ord.Uint32(b), nil
}

// Read64 reads a 64-bit field.
func (s *Site) Read64(off uint64) (uint64, error) {
	b, err := s.field(off, 8)
	if err != nil {
		return 0, err
	}
	return s.ord.Uint64(b), nil
}

// ReadN reads a 1, 2, 4, or 8 byte field.
func (s *Site) ReadN(off uint64, n int) (uint64, error) {
	b, err := s.field(off, n)
	if err != nil {
		return 0, err
	}
	switch n {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(s.ord.Uint16(b)), nil
	case 4:
		return uint64(s.ord.Uint32(b)), nil
	case 8:
		return s.ord.Uint64(b), nil
	}
	return 0, fmt.Errorf("backend: %s reads %d bytes; width must be 1, 2, 4, or 8",
		s.where(), n)
}

// Write32 writes a 32-bit field.
func (s *Site) Write32(off uint64, v uint32) error {
	b, err := s.field(off, 4)
	if err != nil {
		return err
	}
	s.ord.PutUint32(b, v)
	return nil
}

// Write64 writes a 64-bit field.
func (s *Site) Write64(off uint64, v uint64) error {
	b, err := s.field(off, 8)
	if err != nil {
		return err
	}
	s.ord.PutUint64(b, v)
	return nil
}

// WriteN writes a 1, 2, 4, or 8 byte field, truncating v to the width.
func (s *Site) WriteN(off uint64, n int, v uint64) error {
	b, err := s.field(off, n)
	if err != nil {
		return err
	}
	switch n {
	case 1:
		b[0] = uint8(v)
	case 2:
		s.ord.PutUint16(b, uint16(v))
	case 4:
		s.ord.PutUint32(b, uint32(v))
	case 8:
		s.ord.PutUint64(b, v)
	default:
		return fmt.Errorf("backend: %s writes %d bytes; width must be 1, 2, 4, or 8",
			s.where(), n)
	}
	return nil
}

// WritePointer writes a pointer-width absolute value.
//
// On arm64_32 this is four bytes, and a target above 4 GiB is a RangeError
// rather than a silent truncation — an ILP32 image cannot address it, and
// truncating produces a pointer into the wrong page.
func (s *Site) WritePointer(off uint64, v uint64, what string) error {
	if s.word == 4 && v > 0xffffffff {
		return s.rangeError(what, off, int64(v), 32, false, 0)
	}
	return s.WriteN(off, s.word, v)
}

// Insert32 replaces the bits of the 32-bit field at off that mask selects,
// leaving the rest of the instruction alone.
//
// This is the shape almost every instruction-field relocation wants: the
// opcode, the registers, and the addressing mode are already correct in the
// compiler's output, and the linker is filling in one immediate. Rewriting the
// whole word instead means the backend has to reconstruct fields it has no
// reason to know about.
func (s *Site) Insert32(off uint64, value, mask uint32) error {
	cur, err := s.Read32(off)
	if err != nil {
		return err
	}
	return s.Write32(off, (cur&^mask)|(value&mask))
}

// CheckSigned reports whether v fits a signed field of the given width with
// the given number of implicit low zero bits, and returns a RangeError if it
// does not.
//
// The shift is not cosmetic. An arm64 BRANCH26 stores a 26-bit field that the
// processor multiplies by 4, so the value it can express is 28 bits wide but
// only if the low two bits are zero — and a target that is not 4-byte aligned
// is a different error from one that is too far away. Both are caught here.
func (s *Site) CheckSigned(what string, off uint64, v int64, bits, shift uint) error {
	if shift > 0 && v&((1<<shift)-1) != 0 {
		return fmt.Errorf("backend: %s: %s target 0x%x is not %d-byte aligned",
			s.where(), what, uint64(v), 1<<shift)
	}
	lo := -(int64(1) << (bits + shift - 1))
	hi := (int64(1) << (bits + shift - 1)) - 1
	if v < lo || v > hi {
		return s.rangeError(what, off, v, int(bits), true, int(shift))
	}
	return nil
}

// CheckUnsigned reports whether v fits an unsigned field of the given width.
func (s *Site) CheckUnsigned(what string, off uint64, v uint64, bits uint) error {
	if bits < 64 && v >= uint64(1)<<bits {
		return s.rangeError(what, off, int64(v), int(bits), false, 0)
	}
	return nil
}

// SectionAddr returns the assigned address of a named output section, and
// false if the image has no such section.
//
// A backend uses this to find __got or __stubs at Apply time without holding a
// section pointer across the layout fixpoint, where sections can move.
func (s *Site) SectionAddr(n macho.SecName) (uint64, bool) {
	for _, sec := range s.Img.Sections() {
		if sec.Key.Name == n {
			return sec.Addr, true
		}
	}
	return 0, false
}

// where names the atom and its input, for diagnostics.
func (s *Site) where() string {
	if s.Atom == nil {
		return "<no atom>"
	}
	if s.Atom.Input != nil && s.Atom.Input.Name != "" {
		return fmt.Sprintf("%s(%s)", s.Atom.Input.Name, s.Atom)
	}
	return s.Atom.String()
}

func (s *Site) rangeError(what string, off uint64, v int64, bits int, signed bool, shift int) error {
	e := &RangeError{
		Reloc:  what,
		Value:  v,
		Bits:   bits,
		Signed: signed,
		Shift:  shift,
		Addr:   s.PC(off),
	}
	if s.Atom != nil {
		e.Atom = s.Atom.String()
		if s.Atom.Input != nil {
			e.Input = s.Atom.Input.Name
		}
	}
	return e
}

// RangeError reports a value that did not fit the field being written.
//
// It is a distinct type rather than a formatted string because it is the
// diagnostic a user is most likely to have to act on — "your image outgrew the
// branch range" is a real, fixable condition — and link wraps it with the
// input file to produce a message that names both the instruction and the
// object it came from.
type RangeError struct {
	// Reloc is the relocation type's name, e.g. "ARM64_RELOC_BRANCH26".
	Reloc string

	// Value is the value that did not fit: a displacement for a pc-relative
	// field, an address for an absolute one.
	Value int64

	// Bits is the width of the field, before the implicit shift.
	Bits int

	// Signed reports whether the field is two's complement.
	Signed bool

	// Shift is the number of implicit low zero bits, so the expressible range
	// is Bits+Shift wide. It is 2 for an arm64 branch and 0 for most else.
	Shift int

	// Addr is the virtual address of the field.
	Addr uint64

	// Atom and Input name where the relocation came from. Either may be empty.
	Atom  string
	Input string
}

func (e *RangeError) Error() string {
	kind := "unsigned"
	if e.Signed {
		kind = "signed"
	}
	where := ""
	switch {
	case e.Input != "" && e.Atom != "":
		where = fmt.Sprintf(" in %s(%s)", e.Input, e.Atom)
	case e.Atom != "":
		where = fmt.Sprintf(" in %s", e.Atom)
	}
	scaled := ""
	if e.Shift > 0 {
		scaled = fmt.Sprintf(" scaled by %d", 1<<e.Shift)
	}
	return fmt.Sprintf("backend: %s at 0x%x%s: 0x%x does not fit a %d-bit %s field%s",
		e.Reloc, e.Addr, where, e.Value, e.Bits, kind, scaled)
}