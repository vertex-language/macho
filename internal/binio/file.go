package binio

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// File is an io.ReaderAt of known size.
//
// Knowing the size up front is what makes every read bounded: a reader with no
// declared size cannot distinguish "past the end" from "not yet available",
// and a Mach-O parser needs that distinction to reject a crafted offset.
type File struct {
	r      io.ReaderAt
	size   int64
	closer io.Closer // non-nil only when File opened the underlying file
}

// NewFile wraps an io.ReaderAt whose size is already known. Closing the result
// does not close r.
func NewFile(r io.ReaderAt, size int64) *File {
	return &File{r: r, size: size}
}

// Open opens a file for reading and stats it for its size. The returned File
// owns the descriptor; Close closes it.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &File{r: f, size: fi.Size(), closer: f}, nil
}

// Size returns the total size of the file.
func (f *File) Size() int64 { return f.size }

// Close releases the underlying file if this File opened it, and is a no-op
// otherwise.
func (f *File) Close() error {
	if f.closer != nil {
		return f.closer.Close()
	}
	return nil
}

// Extent returns a view covering the whole file.
func (f *File) Extent() Extent {
	return Extent{r: f.r, base: 0, size: f.size}
}

// Slice returns a view of n bytes starting at off, bounds-checked against the
// file size.
func (f *File) Slice(off, n int64) (Extent, error) {
	return f.Extent().Slice(off, n)
}

// Extent is a bounds-checked window into an io.ReaderAt.
//
// An Extent is what lets one slice of a universal file be parsed in place: the
// slice's reader is the whole file, but every offset inside the slice is
// relative to the slice's base and cannot reach outside it. That is why
// obj.NewFile takes an Extent rather than a []byte — a fat member never has to
// be copied out to be parsed, and a member cannot read its neighbour.
//
// Extent is a value type and is safe to copy.
type Extent struct {
	r    io.ReaderAt
	base int64
	size int64
}

// NewExtent builds an Extent directly over a reader.
func NewExtent(r io.ReaderAt, base, size int64) Extent {
	return Extent{r: r, base: base, size: size}
}

// ExtentOf returns an Extent over an in-memory buffer. It is the bridge for
// callers that already hold the bytes, such as a linker fed a generated object.
func ExtentOf(data []byte) Extent {
	return Extent{r: bytesReaderAt(data), base: 0, size: int64(len(data))}
}

// Base returns the offset of the extent within its underlying reader.
//
// This is the value a parser records so that a file offset read out of a load
// command can be resolved against the enclosing file — the field obj.File
// needs and currently lacks.
func (e Extent) Base() int64 { return e.base }

// Size returns the length of the extent.
func (e Extent) Size() int64 { return e.size }

// Valid reports whether e has a reader behind it.
func (e Extent) Valid() bool { return e.r != nil }

// ReadAt implements io.ReaderAt with offsets relative to the extent's base.
// A read that would cross either end of the extent fails.
func (e Extent) ReadAt(p []byte, off int64) (int, error) {
	if e.r == nil {
		return 0, fmt.Errorf("binio: read from zero Extent")
	}
	if off < 0 || off > e.size || int64(len(p)) > e.size-off {
		return 0, &BoundsError{
			Op:        "extent read",
			Off:       e.base + off,
			Want:      int64(len(p)),
			Available: e.size - min64(off, e.size),
		}
	}
	return e.r.ReadAt(p, e.base+off)
}

// Slice returns a sub-extent of n bytes starting at off.
func (e Extent) Slice(off, n int64) (Extent, error) {
	if off < 0 || n < 0 || off > e.size || n > e.size-off {
		return Extent{}, &BoundsError{
			Op:        "extent slice",
			Off:       e.base + off,
			Want:      n,
			Available: e.size - min64(off, e.size),
		}
	}
	return Extent{r: e.r, base: e.base + off, size: n}, nil
}

// Bytes reads the whole extent into memory.
func (e Extent) Bytes() ([]byte, error) {
	return e.Read(0, e.size)
}

// Read reads n bytes at off into a fresh slice.
func (e Extent) Read(off, n int64) ([]byte, error) {
	if n < 0 || off < 0 || off > e.size || n > e.size-off {
		return nil, &BoundsError{
			Op:        "extent read",
			Off:       e.base + off,
			Want:      n,
			Available: e.size - min64(off, e.size),
		}
	}
	p := make([]byte, n)
	if _, err := e.ReadAt(p, off); err != nil {
		return nil, err
	}
	return p, nil
}

// Head reads up to n bytes from the start of the extent, returning fewer if
// the extent is shorter. It is the read for detection functions, which want to
// classify a short file rather than fail on it.
func (e Extent) Head(n int) ([]byte, error) {
	if int64(n) > e.size {
		n = int(e.size)
	}
	return e.Read(0, int64(n))
}

// Cursor reads the whole extent and returns a Cursor over it, with the
// cursor's base set so that offsets in error messages are file offsets rather
// than extent offsets.
func (e Extent) Cursor(ord binary.ByteOrder) (*Cursor, error) {
	b, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return NewCursorAt(b, ord, e.base), nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// bytesReaderAt adapts a byte slice to io.ReaderAt without copying.
type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(b)) {
		return 0, ErrTruncated
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}