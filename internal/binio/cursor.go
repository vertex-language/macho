package binio

import (
	"encoding/binary"
	"fmt"
)

// Cursor is a bounded, order-aware read head over a byte slice.
//
// A Cursor never panics on a short read and never returns a partial value. It
// records the first failure, returns zero from that point on, and reports it
// from Err. That lets a decoder be written as a straight run of reads:
//
//	c := binio.NewCursor(data, binary.LittleEndian)
//	s.Addr = c.U64()
//	s.Size = c.U64()
//	s.Off  = c.U32()
//	if err := c.Err(); err != nil { return err }
//
// The alternative — checking after every field — is where bounds bugs hide.
type Cursor struct {
	data []byte
	ord  binary.ByteOrder
	pos  int
	base int64 // offset of data[0] within the enclosing file, for error text
	err  error
}

// NewCursor returns a Cursor over data.
func NewCursor(data []byte, ord binary.ByteOrder) *Cursor {
	return &Cursor{data: data, ord: ord}
}

// NewCursorAt is NewCursor for data that is a window into a larger file. base
// is the offset of data[0] in that file and appears in error messages; it does
// not affect Pos or any read.
func NewCursorAt(data []byte, ord binary.ByteOrder, base int64) *Cursor {
	return &Cursor{data: data, ord: ord, base: base}
}

// Order returns the byte order the cursor decodes with.
func (c *Cursor) Order() binary.ByteOrder { return c.ord }

// Len returns the total size of the underlying data.
func (c *Cursor) Len() int { return len(c.data) }

// Pos returns the current offset within the data.
func (c *Cursor) Pos() int { return c.pos }

// Base returns the offset of the data within its enclosing file.
func (c *Cursor) Base() int64 { return c.base }

// Remaining returns the number of unread bytes.
func (c *Cursor) Remaining() int {
	if c.err != nil {
		return 0
	}
	return len(c.data) - c.pos
}

// Err returns the first error the cursor hit, or nil.
func (c *Cursor) Err() error { return c.err }

// OK reports whether the cursor has not yet failed.
func (c *Cursor) OK() bool { return c.err == nil }

// fail latches err if this is the first failure.
func (c *Cursor) fail(err error) {
	if c.err == nil {
		c.err = err
	}
}

// short latches a BoundsError for a read of n bytes at the current position.
func (c *Cursor) short(op string, n int) {
	c.fail(&BoundsError{
		Op:        op,
		Off:       c.base + int64(c.pos),
		Want:      int64(n),
		Available: int64(len(c.data) - c.pos),
	})
}

// take advances by n and returns the consumed slice, or nil on failure.
func (c *Cursor) take(op string, n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > len(c.data)-c.pos {
		c.short(op, n)
		return nil
	}
	b := c.data[c.pos : c.pos+n]
	c.pos += n
	return b
}

// Next returns the next n bytes and advances past them. The result aliases the
// underlying data and must not be mutated. It returns nil on failure.
func (c *Cursor) Next(n int) []byte { return c.take("next", n) }

// Skip advances by n bytes without reading them.
func (c *Cursor) Skip(n int) { c.take("skip", n) }

// Seek moves the read head to an absolute offset within the data.
func (c *Cursor) Seek(off int) {
	if c.err != nil {
		return
	}
	if off < 0 || off > len(c.data) {
		c.fail(&BoundsError{
			Op:        "seek",
			Off:       c.base + int64(off),
			Want:      0,
			Available: int64(len(c.data)),
		})
		return
	}
	c.pos = off
}

// Align advances to the next multiple of n, which must be a power of two.
// Padding bytes are not checked for zero; callers that care check them.
func (c *Cursor) Align(n int) {
	if c.err != nil || n <= 1 {
		return
	}
	if pad := (n - c.pos%n) % n; pad != 0 {
		c.take("align", pad)
	}
}

// Sub returns an independent Cursor over the next n bytes and advances past
// them. The sub-cursor cannot read beyond its window no matter what its
// contents claim, which is what makes a nested structure — a segment command
// and its section array, a load command and its payload — safe to decode.
//
// A failure inside the sub-cursor does not propagate; call Fold to merge it.
func (c *Cursor) Sub(n int) *Cursor {
	b := c.take("sub", n)
	if b == nil {
		return &Cursor{ord: c.ord, err: c.err}
	}
	return &Cursor{data: b, ord: c.ord, base: c.base + int64(c.pos-n)}
}

// Fold latches sub's error into c. Use it after decoding through a Sub cursor
// when the caller wants one error to check.
func (c *Cursor) Fold(sub *Cursor) {
	if sub != nil && sub.err != nil {
		c.fail(sub.err)
	}
}

// At returns a Cursor over the data starting at an absolute offset, without
// moving the receiver.
func (c *Cursor) At(off int) *Cursor {
	if c.err != nil {
		return &Cursor{ord: c.ord, err: c.err}
	}
	if off < 0 || off > len(c.data) {
		return &Cursor{ord: c.ord, err: &BoundsError{
			Op:        "at",
			Off:       c.base + int64(off),
			Available: int64(len(c.data)),
		}}
	}
	return &Cursor{data: c.data[off:], ord: c.ord, base: c.base + int64(off)}
}

// Count validates a declared element count against the remaining bytes and
// returns it as an int.
//
// Call this before allocating anything sized by the count. It rejects both an
// overflowing multiplication and a product larger than what is left, so a
// hostile nsects or ncmds fails here rather than in make().
func (c *Cursor) Count(n uint64, elemSize int, what string) (int, bool) {
	if c.err != nil {
		return 0, false
	}
	if elemSize <= 0 {
		return int(n), true
	}
	avail := int64(len(c.data) - c.pos)
	const maxInt64 = 1<<63 - 1
	if n > uint64(maxInt64)/uint64(elemSize) || int64(n)*int64(elemSize) > avail {
		c.fail(&CountError{What: what, Count: n, ElemSize: elemSize, Available: avail})
		return 0, false
	}
	return int(n), true
}

// Fixed-width reads. Each returns zero and latches an error past the end.

func (c *Cursor) U8() uint8 {
	b := c.take("u8", 1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (c *Cursor) U16() uint16 {
	b := c.take("u16", 2)
	if b == nil {
		return 0
	}
	return c.ord.Uint16(b)
}

func (c *Cursor) U32() uint32 {
	b := c.take("u32", 4)
	if b == nil {
		return 0
	}
	return c.ord.Uint32(b)
}

func (c *Cursor) U64() uint64 {
	b := c.take("u64", 8)
	if b == nil {
		return 0
	}
	return c.ord.Uint64(b)
}

func (c *Cursor) I8() int8   { return int8(c.U8()) }
func (c *Cursor) I16() int16 { return int16(c.U16()) }
func (c *Cursor) I32() int32 { return int32(c.U32()) }
func (c *Cursor) I64() int64 { return int64(c.U64()) }

// UintN reads a 1, 2, 4, or 8 byte unsigned value.
//
// This is how a width-dependent field is decoded without binio knowing what a
// Width is: internal/format translates macho.Width into a byte count and calls
// through here.
func (c *Cursor) UintN(n int) uint64 {
	switch n {
	case 1:
		return uint64(c.U8())
	case 2:
		return uint64(c.U16())
	case 4:
		return uint64(c.U32())
	case 8:
		return c.U64()
	}
	c.fail(fmt.Errorf("binio: UintN(%d): width must be 1, 2, 4, or 8", n))
	return 0
}

// CString reads a NUL-terminated string and advances past the NUL. Running out
// of data before a NUL is a truncation error, not an untermined string.
func (c *Cursor) CString() string {
	if c.err != nil {
		return ""
	}
	rest := c.data[c.pos:]
	for i, b := range rest {
		if b == 0 {
			s := string(rest[:i])
			c.pos += i + 1
			return s
		}
	}
	c.short("cstring", len(rest)+1)
	return ""
}

// FixedString reads exactly n bytes and trims at the first NUL.
//
// Mach-O's 16-byte segname and sectname fields are NUL-padded but are not
// NUL-terminated when the name is exactly 16 bytes long, so a CString read of
// one would run into the next field. This is the correct reader for them.
func (c *Cursor) FixedString(n int) string {
	b := c.take("fixed string", n)
	if b == nil {
		return ""
	}
	for i, ch := range b {
		if ch == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Bytes returns a copy of the next n bytes, or nil on failure. Use Next when a
// copy is not needed.
func (c *Cursor) Bytes(n int) []byte {
	b := c.take("bytes", n)
	if b == nil {
		return nil
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

// Rest returns the unread remainder and advances to the end.
func (c *Cursor) Rest() []byte {
	if c.err != nil {
		return nil
	}
	b := c.data[c.pos:]
	c.pos = len(c.data)
	return b
}