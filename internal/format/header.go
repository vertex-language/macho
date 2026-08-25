package format

import (
	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// MachHeader is struct mach_header / mach_header_64.
//
// Reserved exists only in the 64-bit form. It is kept in the struct so a
// round-trip preserves it, but HeaderSize is the only code that knows it is
// conditional.
type MachHeader struct {
	Magic      macho.Magic
	CPU        macho.CPU
	SubCPU     macho.SubCPU
	FileType   macho.FileType
	NCmds      uint32
	SizeOfCmds uint32
	Flags      macho.Flags
	Reserved   uint32 // 64-bit only
}

// Header sizes. These two numbers are the reason this package exists.
const (
	headerSize32 = 28
	headerSize64 = 32
)

// HeaderSize returns the on-disk size of a Mach-O header.
func HeaderSize(w macho.Width) int {
	if w.Wide() {
		return headerSize64
	}
	return headerSize32
}

// Decode reads a Mach-O header.
//
// Width is not a parameter: it is read from the magic, which is the first
// field. A header whose magic is unrecognized is macho.ErrNotMachO rather than
// a decode with a guessed width.
//
// The cursor's byte order is used for every field after the magic. The caller
// is responsible for having built the cursor with the order the magic implies;
// DecodeHeader does that and is the entry point most callers want.
func (h *MachHeader) Decode(c *binio.Cursor) error {
	h.Magic = macho.Magic(c.U32())
	if !h.Magic.Valid() {
		return macho.ErrNotMachO
	}
	h.CPU = macho.CPU(c.U32())
	h.SubCPU = macho.SubCPU(c.U32())
	h.FileType = macho.FileType(c.U32())
	h.NCmds = c.U32()
	h.SizeOfCmds = c.U32()
	h.Flags = macho.Flags(c.U32())
	if h.Magic.Width().Wide() {
		h.Reserved = c.U32()
	}
	return c.Err()
}

// Encode writes a Mach-O header. The width comes from h.Magic, so a header
// with a 64-bit magic always gets its reserved word.
func (h *MachHeader) Encode(b *binio.Buf) {
	b.U32(uint32(h.Magic))
	b.U32(uint32(h.CPU))
	b.U32(uint32(h.SubCPU))
	b.U32(uint32(h.FileType))
	b.U32(h.NCmds)
	b.U32(h.SizeOfCmds)
	b.U32(uint32(h.Flags))
	if h.Magic.Width().Wide() {
		b.U32(h.Reserved)
	}
}

// Width returns the width implied by the header's magic.
func (h *MachHeader) Width() macho.Width { return h.Magic.Width() }

// Size returns the on-disk size of this header.
func (h *MachHeader) Size() int { return HeaderSize(h.Magic.Width()) }

// DecodeHeader reads a Mach-O header from raw bytes, establishing the byte
// order from the magic before decoding anything else.
//
// This is the correct entry point for opening a file: it verifies the magic
// before trusting the byte order the magic implies, so a corrupt first word
// cannot steer the rest of the decode.
func DecodeHeader(data []byte, base int64) (*MachHeader, error) {
	if len(data) < headerSize32 {
		return nil, macho.ErrShortHeader
	}
	// Probe the magic little-endian first; the four constants are defined in
	// terms of that decode, so this identifies the real order.
	m := macho.Magic(binio.NewCursor(data, macho.LittleEndian.Order()).U32())
	if !m.Valid() {
		return nil, macho.ErrNotMachO
	}
	if len(data) < HeaderSize(m.Width()) {
		return nil, macho.ErrShortHeader
	}
	c := binio.NewCursorAt(data, m.Endian().Order(), base)
	var h MachHeader
	if err := h.Decode(c); err != nil {
		return nil, err
	}
	return &h, nil
}

// LoadCmdHeader is struct load_command: the two fields every load command
// begins with.
type LoadCmdHeader struct {
	Cmd     macho.LoadCmd
	CmdSize uint32
}

// LoadCmdHeaderSize is the size of struct load_command. A cmdsize smaller than
// this cannot be valid, since the command does not contain its own header.
const LoadCmdHeaderSize = 8

// Decode reads a load command header.
func (h *LoadCmdHeader) Decode(c *binio.Cursor) error {
	h.Cmd = macho.LoadCmd(c.U32())
	h.CmdSize = c.U32()
	return c.Err()
}

// Encode writes a load command header.
func (h *LoadCmdHeader) Encode(b *binio.Buf) {
	b.U32(uint32(h.Cmd))
	b.U32(h.CmdSize)
}

// Valid checks a cmdsize for the two properties that make a load-command walk
// terminate: it must be large enough to contain the header, and it must be
// aligned to the width's requirement.
//
// A walk must also check that cmdsize does not exceed the remaining bytes;
// that is a bounds question and belongs to the caller's cursor, not here. The
// combination is what turns a self-referential cmdsize into an error instead
// of an infinite loop.
func (h *LoadCmdHeader) Valid(w macho.Width) bool {
	if h.CmdSize < LoadCmdHeaderSize {
		return false
	}
	a := uint32(CmdAlign(w))
	return h.CmdSize%a == 0
}

// LCStr is union lc_str: an offset, from the start of the load command, to a
// NUL-terminated string stored in the command's tail.
//
// The string is not stored here because its length is implied by cmdsize, not
// by any field. Resolve reads it out of the command's bytes.
type LCStr uint32

// Resolve reads the string LCStr points at, given the full bytes of the load
// command it belongs to.
func (s LCStr) Resolve(cmd []byte) (string, error) {
	if int(s) > len(cmd) {
		return "", macho.ErrShortHeader
	}
	c := binio.NewCursor(cmd[s:], macho.LittleEndian.Order())
	// The string has no multi-byte fields, so the order is irrelevant.
	str := c.CString()
	return str, c.Err()
}