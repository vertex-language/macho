package fat

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/format"
)

// Member is one slice to place in a universal file.
type Member struct {
	CPU    macho.CPU
	SubCPU macho.SubCPU

	// Data is the slice's bytes, whole and unmodified. A universal file does
	// not rewrite what it contains — offsets inside a slice are relative to
	// the slice, so a Mach-O is byte-identical whether it is thin or one
	// member of a fat file.
	Data []byte

	// Align is the slice's alignment in BYTES and must be a power of two.
	// Zero means infer it; see inferAlign for what that decides and why
	// guessing high is the safe direction.
	Align uint64
}

// Write builds a universal file and writes it.
func Write(w io.Writer, members []Member) error {
	b, err := Bytes(members)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// Bytes builds a universal file in memory.
//
// The 64-bit form is chosen automatically: if any slice's offset or size would
// not fit a uint32, the whole file is promoted to FAT_MAGIC_64. The form is a
// property of the header, not of the individual entry, so one oversized slice
// promotes every descriptor in the file.
func Bytes(members []Member) ([]byte, error) {
	if len(members) == 0 {
		return nil, ErrNoSlices
	}

	entries, err := prepare(members)
	if err != nil {
		return nil, err
	}

	// Lay out assuming the 32-bit form, then check. Promotion only ever grows
	// the descriptor table and therefore only pushes offsets later, so the
	// second layout cannot un-promote and a third pass is impossible.
	wide := false
	place(entries, wide)
	for i := range entries {
		if entries[i].arch.NeedsWide() {
			wide = true
			break
		}
	}
	if wide {
		place(entries, wide)
	}

	b := format.FatBuf()
	h := format.FatHeader{Magic: macho.FAT_MAGIC, NFatArch: uint32(len(entries))}
	if wide {
		h.Magic = macho.FAT_MAGIC_64
	}
	h.Encode(b)
	for i := range entries {
		entries[i].arch.Encode(b, wide)
	}
	for i := range entries {
		e := &entries[i]
		if uint64(b.Len()) > e.arch.Offset {
			return nil, fmt.Errorf("fat: internal layout error: %s wants offset %d, buffer is at %d",
				macho.ArchName(e.arch.CPU, e.arch.SubCPU), e.arch.Offset, b.Len())
		}
		b.Zero(int(e.arch.Offset - uint64(b.Len())))
		b.Raw(e.data)
	}
	if err := b.Err(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// entry is one member with its resolved alignment and assigned position.
type entry struct {
	arch format.FatArch
	data []byte
}

// prepare validates the members and resolves each one's alignment and order.
func prepare(members []Member) ([]entry, error) {
	out := make([]entry, 0, len(members))

	for i, m := range members {
		if len(m.Data) == 0 {
			return nil, fmt.Errorf("fat: member %d (%s) has no contents",
				i, macho.ArchName(m.CPU, m.SubCPU))
		}
		if int64(len(m.Data)) > math.MaxInt64 {
			return nil, errors.New("fat: member is too large to describe")
		}

		align := m.Align
		if align == 0 {
			align = inferAlign(m)
		}
		if align&(align-1) != 0 {
			return nil, fmt.Errorf("%w: %s alignment %d is not a power of two",
				ErrBadAlign, macho.ArchName(m.CPU, m.SubCPU), align)
		}
		log2 := uint32(0)
		for a := align; a > 1; a >>= 1 {
			log2++
		}
		if log2 > MaxAlign {
			return nil, fmt.Errorf("%w: %s wants 2^%d, the maximum is 2^%d",
				ErrBadAlign, macho.ArchName(m.CPU, m.SubCPU), log2, MaxAlign)
		}

		for _, prev := range out {
			if prev.arch.CPU == m.CPU && prev.arch.SubCPU.Base() == m.SubCPU.Base() {
				return nil, fmt.Errorf("%w: %s",
					ErrDuplicateArch, macho.ArchName(m.CPU, m.SubCPU))
			}
		}

		out = append(out, entry{
			arch: format.FatArch{
				CPU:    m.CPU,
				SubCPU: m.SubCPU,
				Size:   uint64(len(m.Data)),
				Align:  log2,
			},
			data: m.Data,
		})
	}

	// Order by ascending alignment, which is what lipo does and is purely a
	// packing decision: placing the loosely aligned slices first means the
	// strictly aligned ones round up over bytes that are already occupied
	// rather than over padding. Selection is graded rather than positional, so
	// nothing about which slice runs depends on this.
	//
	// The tie-break on cputype and subtype is for determinism: two runs over
	// the same inputs must produce the same bytes, or nothing downstream can
	// be diffed or reproducibly built.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := &out[i].arch, &out[j].arch
		if a.Align != b.Align {
			return a.Align < b.Align
		}
		if a.CPU != b.CPU {
			return a.CPU < b.CPU
		}
		return a.SubCPU < b.SubCPU
	})
	return out, nil
}

// place assigns every slice's offset.
func place(entries []entry, wide bool) {
	archSize := format.FatArchSize
	if wide {
		archSize = format.FatArch64Size
	}
	off := uint64(format.FatHeaderSize) + uint64(len(entries))*uint64(archSize)

	for i := range entries {
		a := &entries[i].arch
		align := uint64(1) << a.Align
		off = (off + align - 1) &^ (align - 1)
		a.Offset = off
		off += a.Size
	}
}

// inferAlign guesses a slice's alignment from its contents.
//
// Guessing high is safe and guessing low is not: over-aligning costs padding,
// while under-aligning an executable gives the kernel a mapping it cannot
// satisfy at a page boundary. So the defaults are page alignment for a Mach-O,
// by architecture, rather than anything derived from the file's contents.
//
// lipo does better for objects — it walks the section headers and takes the
// largest section alignment — which is worth doing eventually and would mean
// this package importing obj. Until then an object gets page alignment too,
// which is never wrong, only occasionally wasteful.
func inferAlign(m Member) uint64 {
	const (
		page16K = 1 << 14
		page4K  = 1 << 12
	)
	if isArchive(m.Data) {
		// An archive is not mapped, so it needs only enough alignment for the
		// members inside it to be read; lipo uses 4 bytes.
		return 4
	}
	if !macho.Is(m.Data) {
		// Not something this package recognizes. lipo's default for an unknown
		// file is a single byte, and inventing more would move a slice the
		// caller may have positioned deliberately.
		return 1
	}
	switch m.CPU {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32, macho.CPU_TYPE_ARM:
		return page16K
	}
	return page4K
}

// archiveMagic is the eight bytes every ar archive begins with. A universal
// file may contain archives rather than Mach-O images — that is what a
// universal static library is — so the writer has to recognize one to align it
// correctly.
const archiveMagic = "!<arch>\n"

func isArchive(b []byte) bool {
	return len(b) >= len(archiveMagic) && string(b[:len(archiveMagic)]) == archiveMagic
}