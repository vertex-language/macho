package format

import (
	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// LinkeditData is struct linkedit_data_command.
//
// One structure serves LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
// LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS,
// LC_LINKER_OPTIMIZATION_HINT, LC_DYLD_EXPORTS_TRIE, and
// LC_DYLD_CHAINED_FIXUPS. Only Cmd distinguishes them; the payload's meaning
// is the reader's business, not this layer's.
type LinkeditData struct {
	Cmd      macho.LoadCmd
	CmdSize  uint32
	DataOff  uint32
	DataSize uint32
}

// LinkeditDataSize is the fixed size of struct linkedit_data_command.
const LinkeditDataSize = 16

func (l *LinkeditData) Decode(c *binio.Cursor) error {
	l.Cmd = macho.LoadCmd(c.U32())
	l.CmdSize = c.U32()
	l.DataOff = c.U32()
	l.DataSize = c.U32()
	return c.Err()
}

func (l *LinkeditData) Encode(b *binio.Buf) {
	b.U32(uint32(l.Cmd))
	b.U32(l.CmdSize)
	b.U32(l.DataOff)
	b.U32(l.DataSize)
}

// DyldInfo is struct dyld_info_command, the classic LC_DYLD_INFO_ONLY payload
// descriptor. Modern images use LC_DYLD_CHAINED_FIXUPS instead, but the
// classic path is still the fallback for older deployment targets.
type DyldInfo struct {
	Cmd     macho.LoadCmd
	CmdSize uint32

	RebaseOff    uint32
	RebaseSize   uint32
	BindOff      uint32
	BindSize     uint32
	WeakBindOff  uint32
	WeakBindSize uint32
	LazyBindOff  uint32
	LazyBindSize uint32
	ExportOff    uint32
	ExportSize   uint32
}

// DyldInfoSize is the fixed size of struct dyld_info_command: twelve 32-bit
// fields.
const DyldInfoSize = 48

func (d *DyldInfo) Decode(c *binio.Cursor) error {
	d.Cmd = macho.LoadCmd(c.U32())
	d.CmdSize = c.U32()
	d.RebaseOff = c.U32()
	d.RebaseSize = c.U32()
	d.BindOff = c.U32()
	d.BindSize = c.U32()
	d.WeakBindOff = c.U32()
	d.WeakBindSize = c.U32()
	d.LazyBindOff = c.U32()
	d.LazyBindSize = c.U32()
	d.ExportOff = c.U32()
	d.ExportSize = c.U32()
	return c.Err()
}

func (d *DyldInfo) Encode(b *binio.Buf) {
	b.U32(uint32(d.Cmd))
	b.U32(d.CmdSize)
	b.U32(d.RebaseOff)
	b.U32(d.RebaseSize)
	b.U32(d.BindOff)
	b.U32(d.BindSize)
	b.U32(d.WeakBindOff)
	b.U32(d.WeakBindSize)
	b.U32(d.LazyBindOff)
	b.U32(d.LazyBindSize)
	b.U32(d.ExportOff)
	b.U32(d.ExportSize)
}

// EntryPoint is struct entry_point_command, the LC_MAIN payload.
//
// EntryOff is a file offset from the start of __TEXT, not a virtual address.
// That distinction matters because __TEXT begins at file offset 0 and includes
// the header, so the two differ by the image base.
type EntryPoint struct {
	Cmd       macho.LoadCmd
	CmdSize   uint32
	EntryOff  uint64
	StackSize uint64
}

// EntryPointSize is the fixed size of struct entry_point_command.
const EntryPointSize = 24

func (e *EntryPoint) Decode(c *binio.Cursor) error {
	e.Cmd = macho.LoadCmd(c.U32())
	e.CmdSize = c.U32()
	e.EntryOff = c.U64()
	e.StackSize = c.U64()
	return c.Err()
}

func (e *EntryPoint) Encode(b *binio.Buf) {
	b.U32(uint32(e.Cmd))
	b.U32(e.CmdSize)
	b.U64(e.EntryOff)
	b.U64(e.StackSize)
}

// UUID is struct uuid_command.
type UUID struct {
	Cmd     macho.LoadCmd
	CmdSize uint32
	UUID    [16]byte
}

// UUIDSize is the fixed size of struct uuid_command.
const UUIDSize = 24

func (u *UUID) Decode(c *binio.Cursor) error {
	u.Cmd = macho.LoadCmd(c.U32())
	u.CmdSize = c.U32()
	if b := c.Next(16); b != nil {
		copy(u.UUID[:], b)
	}
	return c.Err()
}

func (u *UUID) Encode(b *binio.Buf) {
	b.U32(uint32(u.Cmd))
	b.U32(u.CmdSize)
	b.Raw(u.UUID[:])
}

// SourceVersion is struct source_version_command. The version packs as
// A.B.C.D.E in 24.10.10.10.10 bits, which is a different encoding from
// macho.Version and is deliberately not unified with it.
type SourceVersion struct {
	Cmd     macho.LoadCmd
	CmdSize uint32
	Version uint64
}

// SourceVersionSize is the fixed size of struct source_version_command.
const SourceVersionSize = 16

func (s *SourceVersion) Decode(c *binio.Cursor) error {
	s.Cmd = macho.LoadCmd(c.U32())
	s.CmdSize = c.U32()
	s.Version = c.U64()
	return c.Err()
}

func (s *SourceVersion) Encode(b *binio.Buf) {
	b.U32(uint32(s.Cmd))
	b.U32(s.CmdSize)
	b.U64(s.Version)
}

// DataInCodeEntry is struct data_in_code_entry, an element of the
// LC_DATA_IN_CODE table. The table is an array of these in __LINKEDIT, located
// by a LinkeditData command.
type DataInCodeEntry struct {
	Offset uint32 // from the start of __TEXT
	Length uint16
	Kind   uint16
}

// DataInCodeEntrySize is the on-disk size of one entry.
const DataInCodeEntrySize = 8

// DICE kind values.
const (
	DICE_KIND_DATA               uint16 = 0x0001
	DICE_KIND_JUMP_TABLE8        uint16 = 0x0002
	DICE_KIND_JUMP_TABLE16       uint16 = 0x0003
	DICE_KIND_JUMP_TABLE32       uint16 = 0x0004
	DICE_KIND_ABS_JUMP_TABLE32   uint16 = 0x0005
)

func (d *DataInCodeEntry) Decode(c *binio.Cursor) error {
	d.Offset = c.U32()
	d.Length = c.U16()
	d.Kind = c.U16()
	return c.Err()
}

func (d *DataInCodeEntry) Encode(b *binio.Buf) {
	b.U32(d.Offset)
	b.U16(d.Length)
	b.U16(d.Kind)
}