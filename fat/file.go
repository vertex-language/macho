// Package fat reads and writes universal (fat) Mach-O files.
//
// A universal file is an uncompressed container: a big-endian header, a table
// of slice descriptors, and the slices themselves at aligned offsets. What it
// contains is not this package's business — a slice is usually a Mach-O image
// or object, but a universal static library holds ar archives, and nothing in
// the format says otherwise. This package therefore validates the container
// and hands back bounded views of the slices without looking inside them.
//
// Fat is a container concern that spans objects and images and belongs to
// neither, which is why it is its own package rather than living under obj or
// image.
//
// # Byte order
//
// The fat header and every arch entry are always big-endian, regardless of the
// byte order of the slices inside. This is the one place the format breaks its
// own rule that byte order is read from a magic, and it is a live trap: a
// reader that inherits the order from the first slice reads nfat_arch
// byte-swapped and concludes the file has several billion architectures in it.
// The cursors and buffers here come from format.FatCursor and format.FatBuf,
// which fix the order rather than accepting one.
package fat

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
)

// Errors this package adds to the macho.ErrFat* set.
var (
	// ErrNoSlices means a universal file declared zero slices, or a writer was
	// asked to build one with no members. Either is a container with nothing
	// in it, which no tool can do anything useful with.
	ErrNoSlices = errors.New("fat: universal file has no slices")

	// ErrDuplicateArch means two slices claim the same (cputype, cpusubtype).
	// Selection could pick either, and two tools that break the tie
	// differently would disagree about what the file contains — the same
	// hazard as an overlap, arrived at from the other direction.
	ErrDuplicateArch = errors.New("fat: two slices with the same architecture")

	// ErrBadAlign means a slice's alignment exponent exceeded the format's
	// maximum, or its offset was not a multiple of its own declared
	// alignment.
	ErrBadAlign = errors.New("fat: invalid slice alignment")

	// ErrSliceBounds means a slice's offset and size do not lie inside the
	// file.
	ErrSliceBounds = errors.New("fat: slice extends past the end of the file")
)

// MaxAlign is the largest alignment exponent a slice may declare. It matches
// cctools' MAXSECTALIGN; lipo rejects anything larger outright.
const MaxAlign = 15

// File is a parsed universal file.
type File struct {
	ext    binio.Extent
	closer io.Closer

	// Magic is FAT_MAGIC or FAT_MAGIC_64. The two differ only in the width of
	// each entry's offset and size fields; the header itself is identical.
	Magic uint32

	// Arches describes every slice, in the order the arch table declares them.
	Arches []Arch
}

// Arch is one slice descriptor.
//
// Align is in BYTES. The wire form is a power-of-two exponent, and AlignLog2
// is that raw value; presenting bytes is the same convention obj.Section and
// obj.SectionHeader use, so an alignment never changes units as it crosses a
// package boundary in this tree.
type Arch struct {
	CPU    macho.CPU
	SubCPU macho.SubCPU

	Offset uint64
	Size   uint64

	Align     uint64
	AlignLog2 uint32

	// Reserved is the trailing word that exists only in the 64-bit form. It is
	// kept so a read-modify-write round-trips it rather than zeroing a field
	// whose meaning may be assigned later.
	Reserved uint32

	index int
	f     *File
}

// Name returns the toolchain arch name for this slice, e.g. "arm64e".
func (a Arch) Name() string { return macho.ArchName(a.CPU, a.SubCPU) }

func (a Arch) String() string {
	return fmt.Sprintf("%s offset=%d size=%d align=2^%d", a.Name(), a.Offset, a.Size, a.AlignLog2)
}

// Caps returns the slice's capability bits — the high byte of cpusubtype.
//
// For arm64e these carry the ptrauth ABI version. They are deliberately not
// folded into SubCPU comparisons: Base strips them for matching and this
// returns them for round-tripping, so a rewritten fat header preserves the ABI
// information a slice was built with.
func (a Arch) Caps() macho.SubCPU { return a.SubCPU.Caps() }

// Extent returns a bounded view of the slice's bytes.
//
// The view reads from the same file the universal header came from, so no
// copy happens and no member can read its neighbour. This is what obj.NewFile
// and image.Read consume.
func (a Arch) Extent() (binio.Extent, error) {
	if a.f == nil {
		return binio.Extent{}, errors.New("fat: Arch has no file behind it")
	}
	return a.f.ext.Slice(int64(a.Offset), int64(a.Size))
}

// Bytes reads the slice into memory. Prefer Extent when the slice will be
// parsed in place, which is the usual case.
func (a Arch) Bytes() ([]byte, error) {
	e, err := a.Extent()
	if err != nil {
		return nil, err
	}
	return e.Bytes()
}

// Open opens a universal file.
func Open(name string) (*File, error) {
	bf, err := binio.Open(name)
	if err != nil {
		return nil, err
	}
	f, err := NewFile(bf.Extent())
	if err != nil {
		bf.Close()
		return nil, err
	}
	f.closer = bf
	return f, nil
}

// NewFile parses a universal file out of an extent.
func NewFile(ext binio.Extent) (*File, error) {
	if !ext.Valid() {
		return nil, errors.New("fat: NewFile called with a zero Extent")
	}

	head, err := ext.Head(format.FatHeaderSize)
	if err != nil {
		return nil, err
	}
	// Is answers for a thin file, and IsFat carries the Java class file
	// disambiguation — 0xCAFEBABE is also the class magic, and without the
	// nfat_arch check every .class file on the system parses as a fat binary.
	if !macho.IsFat(head) {
		if macho.Is(head) {
			return nil, macho.ErrThinFile
		}
		return nil, macho.ErrNotMachO
	}

	var h format.FatHeader
	if err := h.Decode(format.FatCursor(head, ext.Base())); err != nil {
		return nil, err
	}
	if h.NFatArch == 0 {
		return nil, ErrNoSlices
	}

	// The arch table's size is nfat_arch entries wide, and a hostile count has
	// to fail on this arithmetic rather than on the read. Done in uint64 so
	// the multiplication cannot wrap.
	archSize := uint64(h.ArchSize())
	need := uint64(format.FatHeaderSize) + uint64(h.NFatArch)*archSize
	if need > uint64(ext.Size()) {
		return nil, fmt.Errorf("%w: %d slice descriptors need %d bytes, the file is %d",
			macho.ErrShortHeader, h.NFatArch, need, ext.Size())
	}

	table, err := ext.Read(format.FatHeaderSize, int64(need)-format.FatHeaderSize)
	if err != nil {
		return nil, err
	}

	f := &File{ext: ext, Magic: h.Magic}
	c := format.FatCursor(table, ext.Base()+format.FatHeaderSize)
	for i := uint32(0); i < h.NFatArch; i++ {
		var fa format.FatArch
		if err := fa.Decode(c, h.Wide()); err != nil {
			return nil, err
		}
		f.Arches = append(f.Arches, Arch{
			CPU:       fa.CPU,
			SubCPU:    fa.SubCPU,
			Offset:    fa.Offset,
			Size:      fa.Size,
			Align:     1 << fa.Align,
			AlignLog2: fa.Align,
			Reserved:  fa.Reserved,
			index:     int(i),
			f:         f,
		})
	}
	if err := c.Err(); err != nil {
		return nil, err
	}

	if err := f.validate(need); err != nil {
		return nil, err
	}
	return f, nil
}

// Close releases the underlying file if this File opened it.
func (f *File) Close() error {
	if f.closer != nil {
		return f.closer.Close()
	}
	return nil
}

// Wide reports whether the file uses the 64-bit descriptor form.
func (f *File) Wide() bool { return f.Magic == macho.FAT_MAGIC_64 }

// Size returns the total size of the universal file.
func (f *File) Size() int64 { return f.ext.Size() }

// Slice returns a bounded view of slice i.
func (f *File) Slice(i int) (binio.Extent, error) {
	if i < 0 || i >= len(f.Arches) {
		return binio.Extent{}, fmt.Errorf("fat: slice %d of %d", i, len(f.Arches))
	}
	return f.Arches[i].Extent()
}

// validate checks every property that would let two tools disagree about what
// the file contains.
//
// headerEnd is the first byte past the arch table, which is the earliest a
// slice may legally begin.
func (f *File) validate(headerEnd uint64) error {
	size := uint64(f.ext.Size())

	for i := range f.Arches {
		a := &f.Arches[i]

		if a.AlignLog2 > MaxAlign {
			return fmt.Errorf("%w: %s declares 2^%d, the maximum is 2^%d",
				ErrBadAlign, a.Name(), a.AlignLog2, MaxAlign)
		}
		// A slice whose offset does not satisfy its own declared alignment is
		// self-contradictory, and the contradiction matters: a loader that
		// trusts align to compute a mapping and one that trusts offset to
		// find the bytes end up at different addresses.
		if a.Offset%a.Align != 0 {
			return fmt.Errorf("%w: %s at offset %d is not aligned to 2^%d",
				ErrBadAlign, a.Name(), a.Offset, a.AlignLog2)
		}
		// Checked as a subtraction rather than as offset+size so the sum
		// cannot wrap past the end and come back as a small number.
		if a.Offset > size || a.Size > size-a.Offset {
			return fmt.Errorf("%w: %s spans [%d,%d) of a %d-byte file",
				ErrSliceBounds, a.Name(), a.Offset, a.Offset+a.Size, size)
		}
		if a.Size != 0 && a.Offset < headerEnd {
			return fmt.Errorf("%w: %s begins at %d, inside the %d-byte fat header",
				macho.ErrFatOverlap, a.Name(), a.Offset, headerEnd)
		}

		for j := 0; j < i; j++ {
			b := &f.Arches[j]
			if a.CPU == b.CPU && a.SubCPU.Base() == b.SubCPU.Base() {
				return fmt.Errorf("%w: %s appears at index %d and %d",
					ErrDuplicateArch, a.Name(), j, i)
			}
		}
	}

	// Overlap detection is not optional. Two slices sharing a byte is the
	// standard way to make two tools disagree about a file's contents, and
	// both readings are individually well-formed — nothing downstream can
	// detect it, so it has to be caught here.
	//
	// Checked over a sorted copy so the cost is n log n rather than n², and on
	// indices so the reported order matches the file's.
	order := make([]int, len(f.Arches))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(x, y int) bool {
		return f.Arches[order[x]].Offset < f.Arches[order[y]].Offset
	})
	for k := 1; k < len(order); k++ {
		prev, cur := &f.Arches[order[k-1]], &f.Arches[order[k]]
		if prev.Size == 0 || cur.Size == 0 {
			continue
		}
		if prev.Offset+prev.Size > cur.Offset {
			return fmt.Errorf("%w: %s spans [%d,%d) and %s begins at %d",
				macho.ErrFatOverlap,
				prev.Name(), prev.Offset, prev.Offset+prev.Size,
				cur.Name(), cur.Offset)
		}
	}
	return nil
}