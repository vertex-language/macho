package binio

import (
	"encoding/binary"
	"fmt"
)

// Buf is an order-aware append buffer with reservation patches.
//
// Like Cursor it latches errors rather than panicking, so an encoder can be a
// straight run of appends with one check at the end. The errors a Buf can hit
// are all programming errors — a name too long for its field, a bad alignment
// — but they are the kind that produce a subtly wrong file rather than a
// crash, so they are worth surfacing as errors rather than trusting.
type Buf struct {
	b   []byte
	ord binary.ByteOrder
	err error
}

// NewBuf returns an empty Buf.
func NewBuf(ord binary.ByteOrder) *Buf { return &Buf{ord: ord} }

// NewBufSize returns an empty Buf with capacity reserved.
func NewBufSize(ord binary.ByteOrder, capacity int) *Buf {
	return &Buf{b: make([]byte, 0, capacity), ord: ord}
}

// Order returns the byte order the buffer encodes with.
func (b *Buf) Order() binary.ByteOrder { return b.ord }

// Len returns the number of bytes written so far. It is also the offset the
// next append will land at.
func (b *Buf) Len() int { return len(b.b) }

// Bytes returns the accumulated bytes. The result aliases the buffer.
func (b *Buf) Bytes() []byte { return b.b }

// Err returns the first error the buffer hit, or nil.
func (b *Buf) Err() error { return b.err }

// Reset truncates the buffer to zero length, keeping its capacity and
// clearing any error.
func (b *Buf) Reset() {
	b.b = b.b[:0]
	b.err = nil
}

func (b *Buf) fail(err error) {
	if b.err == nil {
		b.err = err
	}
}

func (b *Buf) U8(v uint8) { b.b = append(b.b, v) }

func (b *Buf) U16(v uint16) {
	var t [2]byte
	b.ord.PutUint16(t[:], v)
	b.b = append(b.b, t[:]...)
}

func (b *Buf) U32(v uint32) {
	var t [4]byte
	b.ord.PutUint32(t[:], v)
	b.b = append(b.b, t[:]...)
}

func (b *Buf) U64(v uint64) {
	var t [8]byte
	b.ord.PutUint64(t[:], v)
	b.b = append(b.b, t[:]...)
}

func (b *Buf) I8(v int8)   { b.U8(uint8(v)) }
func (b *Buf) I16(v int16) { b.U16(uint16(v)) }
func (b *Buf) I32(v int32) { b.U32(uint32(v)) }
func (b *Buf) I64(v int64) { b.U64(uint64(v)) }

// UintN appends a 1, 2, 4, or 8 byte unsigned value. It is the mirror of
// Cursor.UintN and the same width-translation point.
func (b *Buf) UintN(n int, v uint64) {
	switch n {
	case 1:
		b.U8(uint8(v))
	case 2:
		b.U16(uint16(v))
	case 4:
		b.U32(uint32(v))
	case 8:
		b.U64(v)
	default:
		b.fail(fmt.Errorf("binio: UintN(%d): width must be 1, 2, 4, or 8", n))
	}
}

// Raw appends bytes verbatim.
func (b *Buf) Raw(p []byte) { b.b = append(b.b, p...) }

// String appends s with no terminator.
func (b *Buf) String(s string) { b.b = append(b.b, s...) }

// CString appends s followed by a NUL.
func (b *Buf) CString(s string) {
	b.b = append(b.b, s...)
	b.b = append(b.b, 0)
}

// FixedString appends s NUL-padded to exactly n bytes.
//
// A string of exactly n bytes is written with no terminator, matching the
// on-disk convention for segname and sectname. A longer string is an error,
// not a truncation: silently trimming a name can collide two distinct
// sections into one.
func (b *Buf) FixedString(s string, n int) {
	if len(s) > n {
		b.fail(fmt.Errorf("%w: %q is %d bytes, field is %d",
			ErrNameTooLong, s, len(s), n))
		b.Zero(n)
		return
	}
	b.b = append(b.b, s...)
	b.Zero(n - len(s))
}

// Zero appends n zero bytes.
func (b *Buf) Zero(n int) {
	if n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		b.b = append(b.b, 0)
	}
}

// Align pads with zeros until the length is a multiple of n. n must be a
// positive power of two.
func (b *Buf) Align(n int) {
	if n <= 1 {
		return
	}
	if n&(n-1) != 0 {
		b.fail(fmt.Errorf("binio: Align(%d): not a power of two", n))
		return
	}
	b.Zero((n - len(b.b)%n) % n)
}

// AlignFrom pads until (base + Len) is a multiple of n. Use it when the
// buffer's contents will land at a nonzero file offset and the alignment is a
// property of the final position, not of the buffer.
func (b *Buf) AlignFrom(base int64, n int) {
	if n <= 1 {
		return
	}
	if n&(n-1) != 0 {
		b.fail(fmt.Errorf("binio: AlignFrom(%d): not a power of two", n))
		return
	}
	pos := (base + int64(len(b.b))) % int64(n)
	b.Zero(int((int64(n) - pos) % int64(n)))
}

// Ref32 is a reserved 32-bit slot that can be filled in later.
//
// Mach-O is full of fields that cannot be known when they are written: a
// segment's filesize before its sections are laid out, a load command's
// cmdsize before its payload is appended, a symtab's stroff before the string
// table is built. Reserve one, keep going, and Set it once the value is known:
//
//	size := b.Reserve32()
//	// ... append the payload ...
//	size.Set(uint32(b.Len() - start))
//
// A Ref holds an offset rather than a pointer, so it survives the buffer
// growing and reallocating underneath it.
type Ref32 struct {
	buf *Buf
	off int
}

// Reserve32 appends four zero bytes and returns a handle to them.
func (b *Buf) Reserve32() *Ref32 {
	off := len(b.b)
	b.U32(0)
	return &Ref32{buf: b, off: off}
}

// Off returns the offset of the reserved slot within the buffer.
func (r *Ref32) Off() int { return r.off }

// Set writes v into the reserved slot.
func (r *Ref32) Set(v uint32) {
	if r == nil || r.buf.err != nil {
		return
	}
	r.buf.ord.PutUint32(r.buf.b[r.off:r.off+4], v)
}

// Ref64 is a reserved 64-bit slot.
type Ref64 struct {
	buf *Buf
	off int
}

// Reserve64 appends eight zero bytes and returns a handle to them.
func (b *Buf) Reserve64() *Ref64 {
	off := len(b.b)
	b.U64(0)
	return &Ref64{buf: b, off: off}
}

// Off returns the offset of the reserved slot within the buffer.
func (r *Ref64) Off() int { return r.off }

// Set writes v into the reserved slot.
func (r *Ref64) Set(v uint64) {
	if r == nil || r.buf.err != nil {
		return
	}
	r.buf.ord.PutUint64(r.buf.b[r.off:r.off+8], v)
}

// ReserveN reserves a width-dependent slot. Set through Ref32 or Ref64 as
// appropriate; RefN dispatches for callers that only know a byte count.
func (b *Buf) ReserveN(n int) *RefN {
	off := len(b.b)
	switch n {
	case 4:
		b.U32(0)
	case 8:
		b.U64(0)
	default:
		b.fail(fmt.Errorf("binio: ReserveN(%d): width must be 4 or 8", n))
		return &RefN{buf: b, off: off, width: 0}
	}
	return &RefN{buf: b, off: off, width: n}
}

// RefN is a reserved slot of 4 or 8 bytes.
type RefN struct {
	buf   *Buf
	off   int
	width int
}

// Off returns the offset of the reserved slot within the buffer.
func (r *RefN) Off() int { return r.off }

// Set writes v into the reserved slot, truncating to the slot's width.
func (r *RefN) Set(v uint64) {
	if r == nil || r.buf.err != nil {
		return
	}
	switch r.width {
	case 4:
		r.buf.ord.PutUint32(r.buf.b[r.off:r.off+4], uint32(v))
	case 8:
		r.buf.ord.PutUint64(r.buf.b[r.off:r.off+8], v)
	}
}

// Patch32 overwrites four bytes at an arbitrary offset already written.
func (b *Buf) Patch32(off int, v uint32) {
	if b.err != nil {
		return
	}
	if off < 0 || off+4 > len(b.b) {
		b.fail(fmt.Errorf("binio: Patch32 at %d: buffer is %d bytes", off, len(b.b)))
		return
	}
	b.ord.PutUint32(b.b[off:off+4], v)
}

// Patch64 overwrites eight bytes at an arbitrary offset already written.
func (b *Buf) Patch64(off int, v uint64) {
	if b.err != nil {
		return
	}
	if off < 0 || off+8 > len(b.b) {
		b.fail(fmt.Errorf("binio: Patch64 at %d: buffer is %d bytes", off, len(b.b)))
		return
	}
	b.ord.PutUint64(b.b[off:off+8], v)
}

// PatchRaw overwrites len(p) bytes at an arbitrary offset already written.
// This is how relocation application and stub patching write into a finished
// output buffer.
func (b *Buf) PatchRaw(off int, p []byte) {
	if b.err != nil {
		return
	}
	if off < 0 || off+len(p) > len(b.b) {
		b.fail(fmt.Errorf("binio: PatchRaw at %d for %d bytes: buffer is %d bytes",
			off, len(p), len(b.b)))
		return
	}
	copy(b.b[off:], p)
}