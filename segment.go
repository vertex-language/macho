package macho

import "strings"

// Prot is a VM protection mask, used for a segment's maxprot and initprot.
//
// Prot is a distinct type from SecAttrs even though both are uint32 on the
// wire. A shared type would let a segment protection leak into a section
// attribute mask, which is a silent miscompile rather than a build error.
type Prot uint32

const (
	VM_PROT_NONE    Prot = 0x0
	VM_PROT_READ    Prot = 0x1
	VM_PROT_WRITE   Prot = 0x2
	VM_PROT_EXECUTE Prot = 0x4
)

func (p Prot) Has(q Prot) bool { return p&q == q }

// String renders p in the "rwx" form otool -l uses, with "---" for none.
func (p Prot) String() string {
	var b [3]byte
	b[0], b[1], b[2] = '-', '-', '-'
	if p.Has(VM_PROT_READ) {
		b[0] = 'r'
	}
	if p.Has(VM_PROT_WRITE) {
		b[1] = 'w'
	}
	if p.Has(VM_PROT_EXECUTE) {
		b[2] = 'x'
	}
	return string(b[:])
}

// SegFlags is the flags field of a segment load command.
type SegFlags uint32

const (
	SG_HIGHVM              SegFlags = 0x1
	SG_FVMLIB              SegFlags = 0x2
	SG_NORELOC             SegFlags = 0x4
	SG_PROTECTED_VERSION_1 SegFlags = 0x8
	SG_READ_ONLY           SegFlags = 0x10 // read-only after fixups
)

// Well-known segment names.
//
// Mach-O does not infer segments from section flags the way ELF does. These
// are named, ordered, and given protections explicitly by the linker.
const (
	SEG_PAGEZERO   = "__PAGEZERO"
	SEG_TEXT       = "__TEXT"
	SEG_DATA_CONST = "__DATA_CONST"
	SEG_DATA       = "__DATA"
	SEG_LINKEDIT   = "__LINKEDIT"
	SEG_OBJC       = "__OBJC"
	SEG_IMPORT     = "__IMPORT"
	SEG_UNIXSTACK  = "__UNIXSTACK"
	SEG_LINKINFO   = "__LINKINFO"
	SEG_ICON       = "__ICON"
	SEG_DWARF      = "__DWARF"
	SEG_AUTH       = "__AUTH"
	SEG_AUTH_CONST = "__AUTH_CONST"
)

// SegNameSize is the width of the segname and sectname fields on the wire.
// Names are NUL-padded and, at exactly 16 bytes, not NUL-terminated.
const SegNameSize = 16

// truncName trims a fixed-width on-disk name field at the first NUL.
func truncName(b []byte) string {
	if i := indexZero(b); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// ValidName reports whether s fits a 16-byte name field. Names longer than 16
// bytes cannot round-trip and must be rejected at the API edge rather than
// silently truncated, since truncation can collide two distinct sections.
func ValidName(s string) bool {
	return len(s) <= SegNameSize && !strings.ContainsRune(s, 0)
}