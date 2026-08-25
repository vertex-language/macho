package macho

// X86_64Reloc is an r_type value in a file whose cputype is CPU_TYPE_X86_64.
type X86_64Reloc uint8

const (
	X86_64_RELOC_UNSIGNED   X86_64Reloc = 0 // absolute address
	X86_64_RELOC_SIGNED     X86_64Reloc = 1 // 32-bit displacement
	X86_64_RELOC_BRANCH     X86_64Reloc = 2 // CALL/JMP, 32-bit pc-relative
	X86_64_RELOC_GOT_LOAD   X86_64Reloc = 3 // MOVQ load of a GOT entry
	X86_64_RELOC_GOT        X86_64Reloc = 4
	X86_64_RELOC_SUBTRACTOR X86_64Reloc = 5 // must be followed by UNSIGNED
	X86_64_RELOC_SIGNED_1   X86_64Reloc = 6 // displacement biased by -1
	X86_64_RELOC_SIGNED_2   X86_64Reloc = 7 // biased by -2
	X86_64_RELOC_SIGNED_4   X86_64Reloc = 8 // biased by -4
	X86_64_RELOC_TLV        X86_64Reloc = 9
)

// Pairs reports whether r must be followed by a partner entry at the same
// address.
func (r X86_64Reloc) Pairs() bool { return r == X86_64_RELOC_SUBTRACTOR }

func (r X86_64Reloc) String() string {
	switch r {
	case X86_64_RELOC_UNSIGNED:
		return "X86_64_RELOC_UNSIGNED"
	case X86_64_RELOC_SIGNED:
		return "X86_64_RELOC_SIGNED"
	case X86_64_RELOC_BRANCH:
		return "X86_64_RELOC_BRANCH"
	case X86_64_RELOC_GOT_LOAD:
		return "X86_64_RELOC_GOT_LOAD"
	case X86_64_RELOC_GOT:
		return "X86_64_RELOC_GOT"
	case X86_64_RELOC_SUBTRACTOR:
		return "X86_64_RELOC_SUBTRACTOR"
	case X86_64_RELOC_SIGNED_1:
		return "X86_64_RELOC_SIGNED_1"
	case X86_64_RELOC_SIGNED_2:
		return "X86_64_RELOC_SIGNED_2"
	case X86_64_RELOC_SIGNED_4:
		return "X86_64_RELOC_SIGNED_4"
	case X86_64_RELOC_TLV:
		return "X86_64_RELOC_TLV"
	}
	return "X86_64_RELOC(?)"
}