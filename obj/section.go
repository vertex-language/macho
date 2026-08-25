package obj

import (
	"fmt"
	"sync"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
)

// maxAlignLog2 is the largest section alignment this reader accepts, as a
// power of two. The field is a full uint32 on disk, so a corrupt one shifts
// past the width of the result; 2 GiB is far beyond any real section and keeps
// the shift defined.
const maxAlignLog2 = 31

// Section is a parsed section header plus access to its contents.
//
// Align is in BYTES, not the log2 form on disk. The write side takes bytes
// too — see obj.SectionHeader — so the log2 encoding never escapes the wire
// edge in either direction, and a caller never has to remember which
// convention a given field uses. AlignLog2 is available for the caller that
// wants the raw value back.
type Section struct {
	// Identity. Section names are not unique across segments, so the pair is
	// the identity and SecName returns it as one value.
	Name    string
	Segment string

	// Index is the 1-based n_sect ordinal, which is how a symbol names this
	// section. It is not the position in Segment.Sections, though for a
	// single-segment object the two agree.
	Index int

	Addr      uint64
	Size      uint64
	Off       uint32 // file offset, from the start of this slice; 0 if zerofill
	Align     uint32 // bytes
	AlignLog2 uint32
	Reloff    uint32
	Nreloc    uint32
	Flags     uint32 // SecType in the low byte, SecAttrs above

	reserved1 uint32
	reserved2 uint32

	f   *File
	seg *Segment

	relocOnce sync.Once
	relocs    []Reloc
	relocErr  error

	atomOnce sync.Once
	atoms    []Atom
	atomErr  error
}

func (f *File) newSection(fs *format.Section, index int) (*Section, error) {
	if fs.Align > maxAlignLog2 {
		return nil, fmt.Errorf("%w: %s,%s declares alignment 2^%d",
			ErrBadSection, fs.Segment, fs.Name, fs.Align)
	}
	return &Section{
		Name:      fs.Name,
		Segment:   fs.Segment,
		Index:     index,
		Addr:      fs.Addr,
		Size:      fs.Size,
		Off:       fs.Off,
		Align:     1 << fs.Align,
		AlignLog2: fs.Align,
		Reloff:    fs.Reloff,
		Nreloc:    fs.Nreloc,
		Flags:     fs.Flags,
		reserved1: fs.Reserved1,
		reserved2: fs.Reserved2,
		f:         f,
	}, nil
}

// SecName returns the section's identity as a (segment, section) pair.
func (s *Section) SecName() macho.SecName { return macho.Sec(s.Segment, s.Name) }

func (s *Section) String() string { return s.SecName().String() }

// Type returns the section type from the packed flags word.
func (s *Section) Type() macho.SecType {
	t, _ := macho.UnpackSecFlags(s.Flags)
	return t
}

// Attrs returns the section attributes from the packed flags word.
func (s *Section) Attrs() macho.SecAttrs {
	_, a := macho.UnpackSecFlags(s.Flags)
	return a
}

// Zerofill reports whether the section occupies no bytes in the file. A
// zerofill section's Off is meaningless and Data returns nil.
func (s *Section) Zerofill() bool { return s.Type().Zerofill() }

// Segment returns the segment command this section belongs to.
func (s *Section) SegmentCmd() *Segment { return s.seg }

// IndirectIndex returns the section's index into the indirect symbol table.
//
// This is reserved1, which is overloaded by section type. It is meaningful
// only for the pointer and stub types — SecType.Indirect reports which — and
// the named accessor exists so that no caller reads reserved1 and hopes.
func (s *Section) IndirectIndex() (uint32, bool) {
	if !s.Type().Indirect() {
		return 0, false
	}
	return s.reserved1, true
}

// StubSize returns the byte size of one entry in an S_SYMBOL_STUBS section.
//
// This is reserved2, the other overload of the reserved fields.
func (s *Section) StubSize() (uint32, bool) {
	if s.Type() != macho.S_SYMBOL_STUBS {
		return 0, false
	}
	return s.reserved2, true
}

// Open returns a bounded view of the section's contents without copying.
//
// A zerofill section has no file bytes at all, so this returns a zero Extent
// and false rather than a window of the wrong length. Use Zerofill to decide
// which case you are in before calling.
func (s *Section) Open() (binio.Extent, bool, error) {
	if s.Zerofill() || s.Size == 0 {
		return binio.Extent{}, false, nil
	}
	e, err := s.f.ext.Slice(int64(s.Off), int64(s.Size))
	if err != nil {
		return binio.Extent{}, false, fmt.Errorf("obj: %s contents: %w", s, err)
	}
	return e, true, nil
}

// Data reads the section's contents into memory.
//
// A zerofill section returns nil with no error: it has a size in memory and no
// bytes on disk, and returning a run of zeros would invent file content that
// does not exist. Callers laying out an image size the gap from Size instead.
func (s *Section) Data() ([]byte, error) {
	e, ok, err := s.Open()
	if err != nil || !ok {
		return nil, err
	}
	return e.Bytes()
}

// Cursor returns a cursor over the section's contents in the file's byte order.
func (s *Section) Cursor() (*binio.Cursor, bool, error) {
	e, ok, err := s.Open()
	if err != nil || !ok {
		return nil, false, err
	}
	c, err := e.Cursor(s.f.Endian().Order())
	return c, err == nil, err
}

// Contains reports whether addr falls inside this section's address range.
// It is how an LOH argument or a scattered relocation's r_value is attributed
// to a section.
func (s *Section) Contains(addr uint64) bool {
	return addr >= s.Addr && addr < s.Addr+s.Size
}