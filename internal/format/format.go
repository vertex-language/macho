// Package format is the one definition of the Mach-O wire format.
//
// Every on-disk structure is defined exactly once here, with symmetric Decode
// and Encode methods and a Size function. obj, fat, link/read.go, and link's
// emitter all go through this package. No literal structure size and no field
// offset appears anywhere else in the tree.
//
// The rule this enforces is narrow but load-bearing: a reader and a writer of
// the same structure cannot drift apart, because they are the same code read
// in two directions. The bug class it removes is a writer that emits 76 bytes
// for a structure the reader consumes 80 bytes of — which produces a file that
// otool parses happily and dyld rejects at launch.
//
// # Width
//
// Structures whose layout varies with pointer width take a macho.Width. The
// width is never stored in a decoded struct: it is passed in by the caller,
// who got it from the file's magic or from the target's CPU. A struct in this
// package is therefore the union of both layouts, with the 32-bit form's
// fields widened to their 64-bit types, and the Size functions are the only
// code that knows which fields shrink.
//
// # Byte order
//
// Byte order is carried by the binio.Cursor or binio.Buf, not passed
// separately, so a decode cannot use a different order than the one the file
// declared. Fat headers are the exception the format makes explicit: they are
// always big-endian regardless of the slices inside them, which is why
// FatHeader and FatArch have their own constructors rather than accepting any
// cursor.
package format

import (
	"errors"
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// ErrWidth means Decode or Encode was called with an invalid macho.Width.
var ErrWidth = errors.New("format: invalid width")

// ptrSize returns the on-disk size of a width-dependent field.
func ptrSize(w macho.Width) (int, error) {
	switch w {
	case macho.Width32:
		return 4, nil
	case macho.Width64:
		return 8, nil
	}
	return 0, fmt.Errorf("%w: %d", ErrWidth, uint8(w))
}

// mustPtrSize is ptrSize for Encode, which latches into the Buf rather than
// returning an error. It returns 0 for an invalid width; callers pass that to
// binio.Buf.UintN, which latches its own error.
func mustPtrSize(w macho.Width) int {
	n, err := ptrSize(w)
	if err != nil {
		return 0
	}
	return n
}

// NameSize is the width of the segname and sectname fields on disk. Names are
// NUL-padded and, at exactly this length, carry no terminator.
const NameSize = 16

// Alignment required of a load command's cmdsize, by width. The format
// guarantees these are the maximum alignment of any load command, forever.
func CmdAlign(w macho.Width) int {
	if w.Wide() {
		return 8
	}
	return 4
}