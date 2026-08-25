package format

import (
	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// RelocSize is the on-disk size of a relocation entry. Both the normal and the
// scattered forms are two 32-bit words, and the size does not vary with
// pointer width — a 64-bit object's relocations are the same eight bytes as a
// 32-bit object's.
const RelocSize = 8

// Reloc is struct relocation_info.
//
// The second word is a bitfield. reloc.h declares it differently for
// big-endian and little-endian builds, which looks like the layout changes
// with byte order — it does not. Big-endian bitfields fill from the most
// significant bit and little-endian from the least, so the two declarations
// produce identical bit positions within the 32-bit value. One set of masks is
// correct for both, applied after the word has been decoded with the file's
// byte order.
type Reloc struct {
	macho.RelocInfo
}

// Decode reads one relocation_info entry.
func (r *Reloc) Decode(c *binio.Cursor) error {
	r.Address = c.I32()
	r.RelocInfo = mergeAddress(r.Address, macho.UnpackRelocWord(c.U32()))
	return c.Err()
}

func mergeAddress(addr int32, info macho.RelocInfo) macho.RelocInfo {
	info.Address = addr
	return info
}

// Encode writes one relocation_info entry.
func (r *Reloc) Encode(b *binio.Buf) {
	b.I32(r.Address)
	b.U32(macho.PackRelocWord(r.RelocInfo))
}

// ScatteredReloc is struct scattered_relocation_info.
//
// The scattered form is used when the referenced address cannot be named by a
// symbol, so r_value carries the address directly instead of a symbol index.
// It is distinguished from the normal form by the top bit of the first word.
type ScatteredReloc struct {
	macho.ScatteredInfo
}

// Bit positions within the first word of a scattered entry. As with Reloc,
// these are the same in both byte orders once the word is decoded.
const (
	scatAddressMask = 0x00ffffff
	scatTypeShift   = 24
	scatLengthShift = 28
	scatPCRelShift  = 30
)

// Decode reads one scattered_relocation_info entry.
func (r *ScatteredReloc) Decode(c *binio.Cursor) error {
	w := c.U32()
	r.Address = w & scatAddressMask
	r.Type = uint8((w >> scatTypeShift) & 0x0f)
	r.Length = macho.RelocLength((w >> scatLengthShift) & 0x3)
	r.PCRel = w&(1<<scatPCRelShift) != 0
	r.Value = c.I32()
	return c.Err()
}

// Encode writes one scattered_relocation_info entry, setting R_SCATTERED.
func (r *ScatteredReloc) Encode(b *binio.Buf) {
	w := macho.R_SCATTERED |
		(r.Address & scatAddressMask) |
		(uint32(r.Type&0x0f) << scatTypeShift) |
		(uint32(r.Length&0x3) << scatLengthShift)
	if r.PCRel {
		w |= 1 << scatPCRelShift
	}
	b.U32(w)
	b.I32(r.Value)
}

// AnyReloc is a relocation entry of either form, discriminated on read.
//
// A relocation array is a mix of both forms and must be walked entry by entry;
// there is no per-section flag saying which encoding is in use.
type AnyReloc struct {
	Scattered bool
	Normal    Reloc
	Scat      ScatteredReloc
}

// Decode reads one relocation entry of either form.
//
// It peeks the first word to pick the form, then rewinds and decodes. The peek
// is why this takes a cursor rather than eight bytes: the discriminant and the
// payload overlap.
func (a *AnyReloc) Decode(c *binio.Cursor) error {
	pos := c.Pos()
	w := c.U32()
	if err := c.Err(); err != nil {
		return err
	}
	c.Seek(pos)
	if macho.IsScattered(w) {
		a.Scattered = true
		return a.Scat.Decode(c)
	}
	a.Scattered = false
	return a.Normal.Decode(c)
}

// Encode writes one relocation entry in whichever form it holds.
func (a *AnyReloc) Encode(b *binio.Buf) {
	if a.Scattered {
		a.Scat.Encode(b)
		return
	}
	a.Normal.Encode(b)
}

// Address returns the section offset the entry applies to, for either form.
func (a *AnyReloc) Address() int64 {
	if a.Scattered {
		return int64(a.Scat.Address)
	}
	return int64(a.Normal.Address)
}

// Type returns the architecture-specific r_type, for either form.
func (a *AnyReloc) Type() uint8 {
	if a.Scattered {
		return a.Scat.Type
	}
	return a.Normal.Type
}