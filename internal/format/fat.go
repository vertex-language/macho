package format

import (
	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// Fat headers are always big-endian.
//
// This is the one place the format breaks its own rule that byte order is read
// from a magic. A universal file containing only little-endian slices still
// has a big-endian fat header, and a reader that inherits the order from the
// first slice will read nfat_arch byte-swapped and conclude the file has
// several billion architectures in it.
//
// The functions here therefore build their own cursors and buffers rather than
// accepting one, so the order cannot be supplied wrongly.

// FatCursor returns a big-endian cursor over data, for reading fat structures.
func FatCursor(data []byte, base int64) *binio.Cursor {
	return binio.NewCursorAt(data, macho.BigEndian.Order(), base)
}

// FatBuf returns a big-endian buffer, for writing fat structures.
func FatBuf() *binio.Buf {
	return binio.NewBuf(macho.BigEndian.Order())
}

// FatHeader is struct fat_header.
type FatHeader struct {
	Magic    uint32
	NFatArch uint32
}

// FatHeaderSize is the on-disk size of struct fat_header.
const FatHeaderSize = 8

func (h *FatHeader) Decode(c *binio.Cursor) error {
	h.Magic = c.U32()
	h.NFatArch = c.U32()
	return c.Err()
}

func (h *FatHeader) Encode(b *binio.Buf) {
	b.U32(h.Magic)
	b.U32(h.NFatArch)
}

// Wide reports whether the header declares 64-bit slice offsets.
func (h *FatHeader) Wide() bool { return h.Magic == macho.FAT_MAGIC_64 }

// ArchSize returns the size of one arch entry for this header's form.
func (h *FatHeader) ArchSize() int {
	if h.Wide() {
		return FatArch64Size
	}
	return FatArchSize
}

// FatArch is struct fat_arch and struct fat_arch_64 unified.
//
// Offset and Size are uint64 here; the 32-bit form narrows them on disk.
// Reserved exists only in the 64-bit form. A writer promotes to FAT_MAGIC_64
// when either field would exceed 4 GB, which is the only reason the 64-bit
// form exists.
type FatArch struct {
	CPU      macho.CPU
	SubCPU   macho.SubCPU
	Offset   uint64
	Size     uint64
	Align    uint32 // log2
	Reserved uint32 // 64-bit only
}

const (
	// FatArchSize is the on-disk size of struct fat_arch.
	FatArchSize = 20
	// FatArch64Size is the on-disk size of struct fat_arch_64.
	FatArch64Size = 32
)

// Decode reads one arch entry. wide selects the 64-bit form and comes from the
// fat header's magic, not from the slice's own width — a fat header can carry
// 32-bit offsets to 64-bit slices.
func (a *FatArch) Decode(c *binio.Cursor, wide bool) error {
	a.CPU = macho.CPU(c.U32())
	a.SubCPU = macho.SubCPU(c.U32())
	if wide {
		a.Offset = c.U64()
		a.Size = c.U64()
		a.Align = c.U32()
		a.Reserved = c.U32()
	} else {
		a.Offset = uint64(c.U32())
		a.Size = uint64(c.U32())
		a.Align = c.U32()
	}
	return c.Err()
}

// Encode writes one arch entry.
func (a *FatArch) Encode(b *binio.Buf, wide bool) {
	b.U32(uint32(a.CPU))
	b.U32(uint32(a.SubCPU))
	if wide {
		b.U64(a.Offset)
		b.U64(a.Size)
		b.U32(a.Align)
		b.U32(a.Reserved)
	} else {
		b.U32(uint32(a.Offset))
		b.U32(uint32(a.Size))
		b.U32(a.Align)
	}
}

// NeedsWide reports whether this entry cannot be expressed in the 32-bit form.
// A writer checks every entry and promotes the whole file if any says yes,
// since the form is a property of the header, not of the individual slice.
func (a *FatArch) NeedsWide() bool {
	const max32 = 1<<32 - 1
	return a.Offset > max32 || a.Size > max32
}

// End returns the first byte past this slice.
func (a *FatArch) End() uint64 { return a.Offset + a.Size }

// Overlaps reports whether two slices share any byte. Overlap detection is not
// optional: a crafted overlap is the standard way to make two tools disagree
// about what a file contains, and both readings are individually well-formed.
func (a *FatArch) Overlaps(b *FatArch) bool {
	return a.Offset < b.End() && b.Offset < a.End()
}