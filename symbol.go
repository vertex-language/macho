package macho

// nlist n_type field masks. The field packs four subfields:
//
//	N_STAB:3, N_PEXT:1, N_TYPE:3, N_EXT:1
type (
	SymType uint8 // the whole n_type byte
	SymDesc uint16 // the n_desc field
)

const (
	N_STAB SymType = 0xe0 // any bit set means a debugging (stab) entry
	N_PEXT SymType = 0x10 // private external
	N_TYPE SymType = 0x0e // mask for the type bits
	N_EXT  SymType = 0x01 // external
)

// Values of the N_TYPE bits. Note these are the masked values, not shifted:
// compare with (n_type & N_TYPE).
const (
	N_UNDF SymType = 0x0 // undefined; n_sect == NO_SECT
	N_ABS  SymType = 0x2 // absolute; n_sect == NO_SECT
	N_INDR SymType = 0xa // indirect; n_value indexes the string table
	N_PBUD SymType = 0xc // prebound undefined
	N_SECT SymType = 0xe // defined in section n_sect
)

// Section ordinal bounds. n_sect is a single byte, which is why the object
// writer must reject a file with more than 255 sections: overflow silently
// rebinds every symbol rather than failing.
const (
	NO_SECT  = 0
	MAX_SECT = 255
)

// Stab reports whether t is a debugging entry, in which case the whole n_type
// byte is a stab value from <mach-o/stab.h> and N_TYPE does not apply.
func (t SymType) Stab() bool { return t&N_STAB != 0 }

// Type returns the N_TYPE bits. It is meaningless when Stab is true.
func (t SymType) Type() SymType { return t & N_TYPE }

func (t SymType) Ext() bool  { return t&N_EXT != 0 }
func (t SymType) Pext() bool { return t&N_PEXT != 0 }

// Reference type bits of n_desc, for undefined symbols.
const (
	REFERENCE_TYPE SymDesc = 0x7

	REFERENCE_FLAG_UNDEFINED_NON_LAZY         SymDesc = 0
	REFERENCE_FLAG_UNDEFINED_LAZY             SymDesc = 1
	REFERENCE_FLAG_DEFINED                    SymDesc = 2
	REFERENCE_FLAG_PRIVATE_DEFINED            SymDesc = 3
	REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY SymDesc = 4
	REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY     SymDesc = 5
)

// Individual n_desc bits.
//
// Note two pairs of aliases that are genuinely the same bit used for
// non-overlapping purposes: N_NO_DEAD_STRIP / N_DESC_DISCARDED at 0x0020, and
// N_WEAK_DEF / N_REF_TO_WEAK at 0x0080. Which meaning applies depends on
// whether the symbol is defined and on the file type.
const (
	N_ARM_THUMB_DEF        SymDesc = 0x0008
	REFERENCED_DYNAMICALLY SymDesc = 0x0010
	N_NO_DEAD_STRIP        SymDesc = 0x0020 // in MH_OBJECT: never dead-strip
	N_DESC_DISCARDED       SymDesc = 0x0020 // dyld-internal, never on disk
	N_WEAK_REF             SymDesc = 0x0040
	N_WEAK_DEF             SymDesc = 0x0080 // on a definition
	N_REF_TO_WEAK          SymDesc = 0x0080 // on a reference
	N_SYMBOL_RESOLVER      SymDesc = 0x0100
	N_ALT_ENTRY            SymDesc = 0x0200
)

func (d SymDesc) Has(b SymDesc) bool { return d&b == b }

// RefType returns the REFERENCE_TYPE bits.
func (d SymDesc) RefType() SymDesc { return d & REFERENCE_TYPE }

// LibOrdinal is the two-level-namespace library ordinal carried in the high 8
// bits of n_desc.
//
// Under MH_TWOLEVEL an undefined symbol names the library it is expected
// from, so the ordinal is part of symbol identity, not a field patched on at
// emit time. Ordinals for real libraries start at 1 and index the
// LC_LOAD_DYLIB and friends in the order they appear in the load commands.
type LibOrdinal uint8

const (
	SELF_LIBRARY_ORDINAL   LibOrdinal = 0x00
	MAX_LIBRARY_ORDINAL    LibOrdinal = 0xfd
	DYNAMIC_LOOKUP_ORDINAL LibOrdinal = 0xfe
	EXECUTABLE_ORDINAL     LibOrdinal = 0xff
)

// GetLibraryOrdinal extracts the ordinal from an n_desc value.
func GetLibraryOrdinal(d SymDesc) LibOrdinal { return LibOrdinal(d >> 8) }

// SetLibraryOrdinal returns d with its ordinal replaced.
func SetLibraryOrdinal(d SymDesc, o LibOrdinal) SymDesc {
	return (d & 0x00ff) | (SymDesc(o) << 8)
}

// GetCommAlign extracts the log2 alignment of a common symbol from n_desc.
// It occupies the low nibble of the same high byte the library ordinal uses;
// the two are never both meaningful, since a common symbol is undefined and
// not two-level bound.
func GetCommAlign(d SymDesc) uint8 { return uint8((d >> 8) & 0x0f) }

// SetCommAlign returns d with the common-symbol alignment replaced.
func SetCommAlign(d SymDesc, align uint8) SymDesc {
	return (d & 0xf0ff) | (SymDesc(align&0x0f) << 8)
}

func (o LibOrdinal) String() string {
	switch o {
	case SELF_LIBRARY_ORDINAL:
		return "self"
	case DYNAMIC_LOOKUP_ORDINAL:
		return "dynamic-lookup"
	case EXECUTABLE_ORDINAL:
		return "executable"
	}
	return "ordinal"
}

// Indirect symbol table sentinel values, used in place of a symbol index.
const (
	INDIRECT_SYMBOL_LOCAL uint32 = 0x80000000
	INDIRECT_SYMBOL_ABS   uint32 = 0x40000000
)