package macho

// ARM64Reloc is an r_type value in a file whose cputype is CPU_TYPE_ARM64 or
// CPU_TYPE_ARM64_32.
type ARM64Reloc uint8

const (
	ARM64_RELOC_UNSIGNED            ARM64Reloc = 0  // absolute address
	ARM64_RELOC_SUBTRACTOR          ARM64Reloc = 1  // must be followed by UNSIGNED
	ARM64_RELOC_BRANCH26            ARM64Reloc = 2  // B/BL, ±128 MiB
	ARM64_RELOC_PAGE21              ARM64Reloc = 3  // ADRP
	ARM64_RELOC_PAGEOFF12           ARM64Reloc = 4  // ADD/LDR low 12 bits
	ARM64_RELOC_GOT_LOAD_PAGE21     ARM64Reloc = 5
	ARM64_RELOC_GOT_LOAD_PAGEOFF12  ARM64Reloc = 6
	ARM64_RELOC_POINTER_TO_GOT      ARM64Reloc = 7
	ARM64_RELOC_TLVP_LOAD_PAGE21    ARM64Reloc = 8
	ARM64_RELOC_TLVP_LOAD_PAGEOFF12 ARM64Reloc = 9

	// ARM64_RELOC_ADDEND carries a 24-bit addend in r_symbolnum and must be
	// followed immediately by its BRANCH26, PAGE21, or PAGEOFF12. It is the
	// reason Writer.Close never sorts relocation entries.
	ARM64_RELOC_ADDEND ARM64Reloc = 10

	// ARM64_RELOC_AUTHENTICATED_POINTER is the arm64e ptrauth pointer form.
	// Nothing in this tree emits it yet.
	ARM64_RELOC_AUTHENTICATED_POINTER ARM64Reloc = 11
)

// Pairs reports whether r must be followed by a partner entry at the same
// address. Submitting either half alone is an error at Close.
func (r ARM64Reloc) Pairs() bool {
	return r == ARM64_RELOC_SUBTRACTOR || r == ARM64_RELOC_ADDEND
}

func (r ARM64Reloc) String() string {
	switch r {
	case ARM64_RELOC_UNSIGNED:
		return "ARM64_RELOC_UNSIGNED"
	case ARM64_RELOC_SUBTRACTOR:
		return "ARM64_RELOC_SUBTRACTOR"
	case ARM64_RELOC_BRANCH26:
		return "ARM64_RELOC_BRANCH26"
	case ARM64_RELOC_PAGE21:
		return "ARM64_RELOC_PAGE21"
	case ARM64_RELOC_PAGEOFF12:
		return "ARM64_RELOC_PAGEOFF12"
	case ARM64_RELOC_GOT_LOAD_PAGE21:
		return "ARM64_RELOC_GOT_LOAD_PAGE21"
	case ARM64_RELOC_GOT_LOAD_PAGEOFF12:
		return "ARM64_RELOC_GOT_LOAD_PAGEOFF12"
	case ARM64_RELOC_POINTER_TO_GOT:
		return "ARM64_RELOC_POINTER_TO_GOT"
	case ARM64_RELOC_TLVP_LOAD_PAGE21:
		return "ARM64_RELOC_TLVP_LOAD_PAGE21"
	case ARM64_RELOC_TLVP_LOAD_PAGEOFF12:
		return "ARM64_RELOC_TLVP_LOAD_PAGEOFF12"
	case ARM64_RELOC_ADDEND:
		return "ARM64_RELOC_ADDEND"
	case ARM64_RELOC_AUTHENTICATED_POINTER:
		return "ARM64_RELOC_AUTHENTICATED_POINTER"
	}
	return "ARM64_RELOC(?)"
}