// Package macho defines the identity, constants, and target vocabulary of the
// Mach-O object file format.
//
// This package has no I/O and no dependencies. Every other package in the tree
// imports it; it imports nothing from the tree.
//
// Constants here are hand-seeded subsets, sufficient for arm64, arm64e,
// arm64_32, and x86_64 on Apple platforms. They are not exhaustive. See
// README.md "Known gaps".
package macho

import "encoding/binary"

// Magic identifies a thin Mach-O file and encodes both its width and its byte
// order. The four constants are the value obtained by decoding the first four
// bytes of a file as a little-endian uint32: a big-endian file yields the
// byte-swapped ("CIGAM") form.
type Magic uint32

const (
	MH_MAGIC    Magic = 0xfeedface // 32-bit, little-endian
	MH_CIGAM    Magic = 0xcefaedfe // 32-bit, big-endian
	MH_MAGIC_64 Magic = 0xfeedfacf // 64-bit, little-endian
	MH_CIGAM_64 Magic = 0xcffaedfe // 64-bit, big-endian
)

// Valid reports whether m is one of the four Mach-O magic values.
func (m Magic) Valid() bool {
	switch m {
	case MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64:
		return true
	}
	return false
}

// Width returns the pointer width implied by the magic. It returns the zero
// Width for an invalid magic.
func (m Magic) Width() Width {
	switch m {
	case MH_MAGIC, MH_CIGAM:
		return Width32
	case MH_MAGIC_64, MH_CIGAM_64:
		return Width64
	}
	return 0
}

// Endian returns the byte order implied by the magic. It returns the zero
// Endian for an invalid magic.
//
// Byte order is a property of the individual file and is always read from the
// magic. Fat headers are the one exception in the format and are always
// big-endian; see fat.go.
func (m Magic) Endian() Endian {
	switch m {
	case MH_MAGIC, MH_MAGIC_64:
		return LittleEndian
	case MH_CIGAM, MH_CIGAM_64:
		return BigEndian
	}
	return 0
}

func (m Magic) String() string {
	switch m {
	case MH_MAGIC:
		return "MH_MAGIC"
	case MH_CIGAM:
		return "MH_CIGAM"
	case MH_MAGIC_64:
		return "MH_MAGIC_64"
	case MH_CIGAM_64:
		return "MH_CIGAM_64"
	}
	return "Magic(?)"
}

// Width is the single representation of 32-vs-64 in this tree.
//
// It is never stored in an exported struct. It is always derived, from a magic
// (Magic.Width) or from a CPU type (CPU.Width). There is no independently
// settable width field anywhere in this API, because a width that disagrees
// with its CPU is not a state Mach-O can represent.
type Width uint8

const (
	Width32 Width = iota + 1
	Width64
)

// Wide reports whether w is 64-bit. It is total: the zero Width reports false
// rather than panicking, so a caller that forgot to check Valid gets a wrong
// answer rather than a crash in a decode loop.
func (w Width) Wide() bool { return w == Width64 }

func (w Width) Valid() bool { return w == Width32 || w == Width64 }

// Bits returns 32 or 64, or 0 for the zero Width.
func (w Width) Bits() int {
	switch w {
	case Width32:
		return 32
	case Width64:
		return 64
	}
	return 0
}

func (w Width) String() string {
	switch w {
	case Width32:
		return "32"
	case Width64:
		return "64"
	}
	return "?"
}

// Endian is the byte order of one Mach-O file.
type Endian uint8

const (
	LittleEndian Endian = iota + 1
	BigEndian
)

func (e Endian) Valid() bool { return e == LittleEndian || e == BigEndian }

// Order returns the binary.ByteOrder for e. It is total: the zero Endian
// yields binary.LittleEndian rather than nil, so a decoder cannot nil-panic
// partway through a structure. Check Valid if the distinction matters.
func (e Endian) Order() binary.ByteOrder {
	if e == BigEndian {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func (e Endian) String() string {
	switch e {
	case LittleEndian:
		return "little"
	case BigEndian:
		return "big"
	}
	return "?"
}