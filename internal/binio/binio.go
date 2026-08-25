// Package binio is bounded byte access: a read cursor that cannot run off the
// end of its data, a write buffer with reservation patches, LEB128, and a
// bounds-checked view over an io.ReaderAt.
//
// It knows nothing about Mach-O. It does not import the macho package, and it
// must not — the layering is that internal/format imports both, and binio
// imports neither.
//
// Two conventions run through the package:
//
// Errors latch. A Cursor accumulates the first error and then no-ops, so a
// decoder can read a whole structure straight through and check once at the
// end rather than testing every field. All reads after the first failure
// return zero values.
//
// Counts are checked before allocation. A declared element count that cannot
// fit in the remaining bytes is a CountError, raised before anything is
// sized or allocated, so a crafted header cannot turn into a large make().
package binio

import (
	"errors"
	"fmt"
)

// ErrTruncated is the root of every bounds failure in this package. Bounds
// errors carry context but unwrap to this, so callers match with errors.Is.
var ErrTruncated = errors.New("binio: read past end of data")

// ErrOverflow means a LEB128 value did not fit in 64 bits.
var ErrOverflow = errors.New("binio: LEB128 value overflows 64 bits")

// ErrNameTooLong means a string did not fit a fixed-width field.
var ErrNameTooLong = errors.New("binio: string does not fit fixed-width field")

// BoundsError reports a read that ran past the end of the available data.
type BoundsError struct {
	Op        string // what was being read, e.g. "u32" or "section name"
	Off       int64  // offset the read started at
	Want      int64  // bytes needed
	Available int64  // bytes actually left
}

func (e *BoundsError) Error() string {
	return fmt.Sprintf("binio: %s at offset %d wants %d bytes, %d available",
		e.Op, e.Off, e.Want, e.Available)
}

func (e *BoundsError) Unwrap() error { return ErrTruncated }

// CountError reports a declared element count that cannot fit the data.
//
// It exists so that a header claiming four billion sections fails on the
// arithmetic rather than on the allocation. Every count-driven loop in this
// tree validates through Cursor.Count before it makes a slice.
type CountError struct {
	What      string // what is being counted, e.g. "load commands"
	Count     uint64 // the declared count
	ElemSize  int    // bytes per element
	Available int64  // bytes actually left
}

func (e *CountError) Error() string {
	return fmt.Sprintf("binio: %d %s at %d bytes each do not fit in %d remaining bytes",
		e.Count, e.What, e.ElemSize, e.Available)
}

func (e *CountError) Unwrap() error { return ErrTruncated }