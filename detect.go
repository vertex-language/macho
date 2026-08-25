package macho

import "encoding/binary"

// Byte counts the detection functions need.
const (
	// MagicSize is what Is and IsFat require.
	MagicSize = 4

	// KindPrefix is what KindOf requires: magic, cputype, cpusubtype, filetype.
	KindPrefix = 16
)

// Fat header magic. Both forms are always stored big-endian, regardless of
// the byte order of the slices inside, so these are compared against a
// big-endian decode rather than a little-endian one.
const (
	FAT_MAGIC    uint32 = 0xcafebabe
	FAT_MAGIC_64 uint32 = 0xcafebabf
)

// Kind is a coarse classification of a Mach-O file.
type Kind uint8

const (
	KindUnknown Kind = iota
	KindObject
	KindExecute
	KindDylib
	KindBundle
	KindDSYM
	KindDylibStub
	KindKextBundle
	KindFileset
	KindCore
	KindDylinker
	KindPreload
)

func (k Kind) String() string {
	switch k {
	case KindObject:
		return "object"
	case KindExecute:
		return "executable"
	case KindDylib:
		return "dylib"
	case KindBundle:
		return "bundle"
	case KindDSYM:
		return "dsym"
	case KindDylibStub:
		return "dylib-stub"
	case KindKextBundle:
		return "kext"
	case KindFileset:
		return "fileset"
	case KindCore:
		return "core"
	case KindDylinker:
		return "dylinker"
	case KindPreload:
		return "preload"
	}
	return "unknown"
}

// KindOfFileType maps a filetype to a Kind.
func KindOfFileType(t FileType) Kind {
	switch t {
	case MH_OBJECT:
		return KindObject
	case MH_EXECUTE:
		return KindExecute
	case MH_DYLIB:
		return KindDylib
	case MH_BUNDLE:
		return KindBundle
	case MH_DSYM:
		return KindDSYM
	case MH_DYLIB_STUB:
		return KindDylibStub
	case MH_KEXT_BUNDLE:
		return KindKextBundle
	case MH_FILESET:
		return KindFileset
	case MH_CORE:
		return KindCore
	case MH_DYLINKER:
		return KindDylinker
	case MH_PRELOAD:
		return KindPreload
	}
	return KindUnknown
}

// Is reports whether head begins with a thin Mach-O magic, in either byte
// order and either width. head must be at least MagicSize bytes.
func Is(head []byte) bool {
	if len(head) < MagicSize {
		return false
	}
	return Magic(binary.LittleEndian.Uint32(head)).Valid()
}

// IsFat reports whether head begins with a universal (fat) header.
//
// 0xCAFEBABE is also the Java class file magic, so a raw magic comparison
// misidentifies every .class file on the system as a fat binary. The
// disambiguation is on the next word: in a fat header it is nfat_arch, in a
// class file it is a (minor, major) version pair whose combined value is at
// least 45 — the class format's first version. A fat binary with 45 or more
// slices is not a thing that exists, so the threshold separates them cleanly.
// FAT_MAGIC_64 has no such collision and needs no check.
func IsFat(head []byte) bool {
	if len(head) < 8 {
		// The magic alone is not enough to answer for FAT_MAGIC; require the
		// count word too rather than guessing.
		if len(head) < MagicSize {
			return false
		}
		return binary.BigEndian.Uint32(head) == FAT_MAGIC_64
	}
	switch binary.BigEndian.Uint32(head) {
	case FAT_MAGIC_64:
		return true
	case FAT_MAGIC:
		return binary.BigEndian.Uint32(head[4:]) < javaClassMinVersion
	}
	return false
}

// javaClassMinVersion is the earliest Java class file major version (JDK 1.1).
// Any class file's second word is at least this large; any real fat header's
// is far smaller.
const javaClassMinVersion = 45

// KindOf classifies a thin Mach-O file from its first KindPrefix bytes.
//
// It verifies the magic before trusting the byte order implied by it, so a
// corrupt header yields an error rather than a garbage kind. A fat header
// yields ErrFatFile rather than a misread thin classification.
func KindOf(head []byte) (Kind, error) {
	if len(head) < MagicSize {
		return KindUnknown, ErrShortHeader
	}
	if IsFat(head) {
		return KindUnknown, ErrFatFile
	}
	if len(head) < KindPrefix {
		return KindUnknown, ErrShortHeader
	}
	m := Magic(binary.LittleEndian.Uint32(head))
	if !m.Valid() {
		return KindUnknown, ErrNotMachO
	}
	ord := m.Endian().Order()
	return KindOfFileType(FileType(ord.Uint32(head[12:16]))), nil
}

// TargetOf reads the CPU and SubCPU from a thin header prefix. It does not
// read load commands, so it cannot fill in a platform or version; use it to
// pick a fat slice, not to build a link target.
func TargetOf(head []byte) (CPU, SubCPU, error) {
	if len(head) < KindPrefix {
		return 0, 0, ErrShortHeader
	}
	m := Magic(binary.LittleEndian.Uint32(head))
	if !m.Valid() {
		return 0, 0, ErrNotMachO
	}
	ord := m.Endian().Order()
	return CPU(ord.Uint32(head[4:8])), SubCPU(ord.Uint32(head[8:12])), nil
}