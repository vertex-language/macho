package macho

import "fmt"

// SecType is the low byte of a section's flags field: the section type.
// Types are mutually exclusive — a section has exactly one.
type SecType uint8

// SecAttrs is the high 24 bits of a section's flags field: the section
// attributes. Attributes are not mutually exclusive.
//
// SecType and SecAttrs are separate Go types even though they share one
// uint32 on the wire, and they are packed only at the wire edge in
// internal/format. A shared uint32 lets a type value leak into an attribute
// mask, which no compiler catches.
type SecAttrs uint32

// Masks for splitting a section flags word.
const (
	SECTION_TYPE       uint32 = 0x000000ff
	SECTION_ATTRIBUTES uint32 = 0xffffff00
)

const (
	S_REGULAR                             SecType = 0x0
	S_ZEROFILL                            SecType = 0x1
	S_CSTRING_LITERALS                    SecType = 0x2
	S_4BYTE_LITERALS                      SecType = 0x3
	S_8BYTE_LITERALS                      SecType = 0x4
	S_LITERAL_POINTERS                    SecType = 0x5
	S_NON_LAZY_SYMBOL_POINTERS            SecType = 0x6
	S_LAZY_SYMBOL_POINTERS                SecType = 0x7
	S_SYMBOL_STUBS                        SecType = 0x8
	S_MOD_INIT_FUNC_POINTERS              SecType = 0x9
	S_MOD_TERM_FUNC_POINTERS              SecType = 0xa
	S_COALESCED                           SecType = 0xb
	S_GB_ZEROFILL                         SecType = 0xc
	S_INTERPOSING                         SecType = 0xd
	S_16BYTE_LITERALS                     SecType = 0xe
	S_DTRACE_DOF                          SecType = 0xf
	S_LAZY_DYLIB_SYMBOL_POINTERS          SecType = 0x10
	S_THREAD_LOCAL_REGULAR                SecType = 0x11
	S_THREAD_LOCAL_ZEROFILL               SecType = 0x12
	S_THREAD_LOCAL_VARIABLES              SecType = 0x13
	S_THREAD_LOCAL_VARIABLE_POINTERS      SecType = 0x14
	S_THREAD_LOCAL_INIT_FUNCTION_POINTERS SecType = 0x15
	S_INIT_FUNC_OFFSETS                   SecType = 0x16
)

const (
	SECTION_ATTRIBUTES_USR SecAttrs = 0xff000000
	SECTION_ATTRIBUTES_SYS SecAttrs = 0x00ffff00

	S_ATTR_PURE_INSTRUCTIONS   SecAttrs = 0x80000000
	S_ATTR_NO_TOC              SecAttrs = 0x40000000
	S_ATTR_STRIP_STATIC_SYMS   SecAttrs = 0x20000000
	S_ATTR_NO_DEAD_STRIP       SecAttrs = 0x10000000
	S_ATTR_LIVE_SUPPORT        SecAttrs = 0x08000000
	S_ATTR_SELF_MODIFYING_CODE SecAttrs = 0x04000000
	S_ATTR_DEBUG               SecAttrs = 0x02000000
	S_ATTR_SOME_INSTRUCTIONS   SecAttrs = 0x00000400
	S_ATTR_EXT_RELOC           SecAttrs = 0x00000200
	S_ATTR_LOC_RELOC           SecAttrs = 0x00000100
)

func (a SecAttrs) Has(b SecAttrs) bool { return a&b == b }

// UnpackSecFlags splits an on-disk flags word into its two components.
func UnpackSecFlags(flags uint32) (SecType, SecAttrs) {
	return SecType(flags & SECTION_TYPE), SecAttrs(flags &^ SECTION_TYPE)
}

// PackSecFlags builds an on-disk flags word. Any attribute bits that overlap
// the type byte are dropped rather than corrupting the type.
func PackSecFlags(t SecType, a SecAttrs) uint32 {
	return uint32(t) | (uint32(a) &^ SECTION_TYPE)
}

// Zerofill reports whether a section of type t occupies no file bytes.
// Zerofill sections must be placed last within their segment.
func (t SecType) Zerofill() bool {
	switch t {
	case S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL:
		return true
	}
	return false
}

// HoldsPointers reports whether a section of type t is an array of
// pointers, whatever alignment its inputs declared.
//
// It matters because the declared alignment can be less. clang emits
// __thread_vars with align 1, and the section is three pointers per
// thread-local: a descriptor placed on an odd boundary is read by a
// pointer-width load at the use site, and the answer is whatever
// straddles it. Apple's linker raises the section to pointer alignment
// rather than trusting the input, and so does this one.
//
// S_THREAD_LOCAL_VARIABLES is the descriptor array. The others are the
// pointer tables the indirect symbol table indexes, which are pointers
// by definition.
func (t SecType) HoldsPointers() bool {
	switch t {
	case S_THREAD_LOCAL_VARIABLES,
		S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS,
		S_LAZY_DYLIB_SYMBOL_POINTERS,
		S_THREAD_LOCAL_VARIABLE_POINTERS,
		S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
		S_MOD_INIT_FUNC_POINTERS, S_MOD_TERM_FUNC_POINTERS:
		return true
	}
	return false
}

// Indirect reports whether a section of type t has entries in the indirect
// symbol table, indexed from the section's reserved1 field.
func (t SecType) Indirect() bool {
	switch t {
	case S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS,
		S_LAZY_DYLIB_SYMBOL_POINTERS, S_SYMBOL_STUBS,
		S_THREAD_LOCAL_VARIABLE_POINTERS:
		return true
	}
	return false
}

func (t SecType) String() string {
	if s, ok := secTypeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("SecType(0x%x)", uint8(t))
}

var secTypeNames = map[SecType]string{
	S_REGULAR: "S_REGULAR", S_ZEROFILL: "S_ZEROFILL",
	S_CSTRING_LITERALS: "S_CSTRING_LITERALS", S_4BYTE_LITERALS: "S_4BYTE_LITERALS",
	S_8BYTE_LITERALS: "S_8BYTE_LITERALS", S_LITERAL_POINTERS: "S_LITERAL_POINTERS",
	S_NON_LAZY_SYMBOL_POINTERS: "S_NON_LAZY_SYMBOL_POINTERS",
	S_LAZY_SYMBOL_POINTERS: "S_LAZY_SYMBOL_POINTERS", S_SYMBOL_STUBS: "S_SYMBOL_STUBS",
	S_MOD_INIT_FUNC_POINTERS: "S_MOD_INIT_FUNC_POINTERS",
	S_MOD_TERM_FUNC_POINTERS: "S_MOD_TERM_FUNC_POINTERS",
	S_COALESCED: "S_COALESCED", S_GB_ZEROFILL: "S_GB_ZEROFILL",
	S_INTERPOSING: "S_INTERPOSING", S_16BYTE_LITERALS: "S_16BYTE_LITERALS",
	S_DTRACE_DOF: "S_DTRACE_DOF",
	S_LAZY_DYLIB_SYMBOL_POINTERS: "S_LAZY_DYLIB_SYMBOL_POINTERS",
	S_THREAD_LOCAL_REGULAR: "S_THREAD_LOCAL_REGULAR",
	S_THREAD_LOCAL_ZEROFILL: "S_THREAD_LOCAL_ZEROFILL",
	S_THREAD_LOCAL_VARIABLES: "S_THREAD_LOCAL_VARIABLES",
	S_THREAD_LOCAL_VARIABLE_POINTERS: "S_THREAD_LOCAL_VARIABLE_POINTERS",
	S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",
	S_INIT_FUNC_OFFSETS: "S_INIT_FUNC_OFFSETS",
}

// SecName is the identity of a section: the (segment, section) pair.
//
// Section names are not unique across segments. __DATA,__const and
// __DATA_CONST,__const are different sections and must never collapse into
// one. No API in this tree accepts a bare section name.
type SecName struct {
	Segment string
	Section string
}

// Sec builds a SecName.
func Sec(segment, section string) SecName {
	return SecName{Segment: segment, Section: section}
}

func (n SecName) String() string { return n.Segment + "," + n.Section }

// Valid reports whether both halves fit their 16-byte on-disk fields.
func (n SecName) Valid() bool {
	return ValidName(n.Segment) && ValidName(n.Section) &&
		n.Segment != "" && n.Section != ""
}

// Well-known section names, used with a segment to form a SecName.
const (
	SECT_TEXT           = "__text"
	SECT_STUBS          = "__stubs"
	SECT_STUB_HELPER    = "__stub_helper"
	SECT_CSTRING        = "__cstring"
	SECT_CONST          = "__const"
	SECT_UNWIND_INFO    = "__unwind_info"
	SECT_EH_FRAME       = "__eh_frame"
	SECT_COMPACT_UNWIND = "__compact_unwind"
	SECT_GOT            = "__got"
	SECT_LA_SYMBOL_PTR  = "__la_symbol_ptr"
	SECT_NL_SYMBOL_PTR  = "__nl_symbol_ptr"
	SECT_DATA           = "__data"
	SECT_BSS            = "__bss"
	SECT_COMMON         = "__common"
	SECT_THREAD_PTRS    = "__thread_ptrs"
	SECT_THREAD_VARS    = "__thread_vars"
	SECT_MOD_INIT_FUNC  = "__mod_init_func"
	SECT_MOD_TERM_FUNC  = "__mod_term_func"
	SECT_OBJC_IMAGEINFO = "__objc_imageinfo"
)