package format

import (
	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// SegmentCmd is struct segment_command / segment_command_64, without the
// section array that follows it.
//
// The four address fields are uint64 in both forms; the 32-bit layout narrows
// them on disk and SegmentCmdSize is the only code that knows by how much.
type SegmentCmd struct {
	Cmd      macho.LoadCmd // LC_SEGMENT or LC_SEGMENT_64
	CmdSize  uint32        // includes the trailing section structures
	Name     string
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	MaxProt  macho.Prot
	InitProt macho.Prot
	NSects   uint32
	Flags    macho.SegFlags
}

const (
	segmentCmdSize32 = 56
	segmentCmdSize64 = 72
)

// SegmentCmdSize returns the on-disk size of a segment command's fixed part,
// excluding the section array.
func SegmentCmdSize(w macho.Width) int {
	if w.Wide() {
		return segmentCmdSize64
	}
	return segmentCmdSize32
}

// Decode reads a segment command's fixed part. The cursor is left positioned
// at the first section structure.
func (s *SegmentCmd) Decode(c *binio.Cursor, w macho.Width) error {
	n, err := ptrSize(w)
	if err != nil {
		return err
	}
	s.Cmd = macho.LoadCmd(c.U32())
	s.CmdSize = c.U32()
	s.Name = c.FixedString(NameSize)
	s.VMAddr = c.UintN(n)
	s.VMSize = c.UintN(n)
	s.FileOff = c.UintN(n)
	s.FileSize = c.UintN(n)
	s.MaxProt = macho.Prot(c.U32())
	s.InitProt = macho.Prot(c.U32())
	s.NSects = c.U32()
	s.Flags = macho.SegFlags(c.U32())
	return c.Err()
}

// Encode writes a segment command's fixed part.
func (s *SegmentCmd) Encode(b *binio.Buf, w macho.Width) {
	n := mustPtrSize(w)
	b.U32(uint32(s.Cmd))
	b.U32(s.CmdSize)
	b.FixedString(s.Name, NameSize)
	b.UintN(n, s.VMAddr)
	b.UintN(n, s.VMSize)
	b.UintN(n, s.FileOff)
	b.UintN(n, s.FileSize)
	b.U32(uint32(s.MaxProt))
	b.U32(uint32(s.InitProt))
	b.U32(s.NSects)
	b.U32(uint32(s.Flags))
}

// TotalSize returns the full cmdsize a segment command with nsects sections
// occupies. This is the value that goes in CmdSize, and computing it anywhere
// else is how a segment ends up claiming a size that does not match its
// contents.
func (s *SegmentCmd) TotalSize(w macho.Width) int {
	return SegmentCmdSize(w) + int(s.NSects)*SectionSize(w)
}

// Section is struct section / section_64.
//
// Flags is kept as the raw packed word. Split it with macho.UnpackSecFlags and
// rebuild it with macho.PackSecFlags — this package stores what is on disk,
// and the type/attribute split is a semantic concern one layer up.
//
// Reserved1 and Reserved2 are overloaded by section type: an index into the
// indirect symbol table for pointer and stub sections, and the byte size of a
// stub for S_SYMBOL_STUBS. They are stored raw here; obj and image expose them
// through named accessors so no caller writes Reserved1 and hopes.
type Section struct {
	Name    string
	Segment string
	Addr    uint64
	Size    uint64
	Off     uint32
	Align   uint32 // log2, as on disk
	Reloff  uint32
	Nreloc  uint32
	Flags   uint32 // SecType in the low byte, SecAttrs above it

	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32 // 64-bit only
}

const (
	sectionSize32 = 68
	sectionSize64 = 80
)

// SectionSize returns the on-disk size of a section structure.
//
// The trailing Reserved3 exists only in the 64-bit form, and this function is
// the only place in the tree that knows it. Everything that walks a section
// array — the load-command reader, the segment writer, the cmdsize
// computation — sizes its stride from here.
func SectionSize(w macho.Width) int {
	if w.Wide() {
		return sectionSize64
	}
	return sectionSize32
}

// Decode reads one section structure.
func (s *Section) Decode(c *binio.Cursor, w macho.Width) error {
	n, err := ptrSize(w)
	if err != nil {
		return err
	}
	s.Name = c.FixedString(NameSize)
	s.Segment = c.FixedString(NameSize)
	s.Addr = c.UintN(n)
	s.Size = c.UintN(n)
	s.Off = c.U32()
	s.Align = c.U32()
	s.Reloff = c.U32()
	s.Nreloc = c.U32()
	s.Flags = c.U32()
	s.Reserved1 = c.U32()
	s.Reserved2 = c.U32()
	if w.Wide() {
		s.Reserved3 = c.U32()
	}
	return c.Err()
}

// Encode writes one section structure.
func (s *Section) Encode(b *binio.Buf, w macho.Width) {
	n := mustPtrSize(w)
	b.FixedString(s.Name, NameSize)
	b.FixedString(s.Segment, NameSize)
	b.UintN(n, s.Addr)
	b.UintN(n, s.Size)
	b.U32(s.Off)
	b.U32(s.Align)
	b.U32(s.Reloff)
	b.U32(s.Nreloc)
	b.U32(s.Flags)
	b.U32(s.Reserved1)
	b.U32(s.Reserved2)
	if w.Wide() {
		b.U32(s.Reserved3)
	}
}

// SecName returns the section's identity as a (segment, section) pair.
func (s *Section) SecName() macho.SecName {
	return macho.Sec(s.Segment, s.Name)
}

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

// SetFlags packs a type and attribute set into the flags word.
func (s *Section) SetFlags(t macho.SecType, a macho.SecAttrs) {
	s.Flags = macho.PackSecFlags(t, a)
}