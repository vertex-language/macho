package macho

// Mach-O relocations carry no addend.
//
// There is no r_addend field. The addend lives in the instruction stream at
// r_address, or — on arm64 — travels in a preceding ARM64_RELOC_ADDEND entry.
// Recovering it is a psABI property and belongs behind backend.Backend.Addend,
// not here.

// RelocFormat distinguishes the two on-disk relocation encodings.
type RelocFormat uint8

const (
	// RelocNormal is struct relocation_info: r_address as a signed 32-bit
	// section offset, then a packed word.
	RelocNormal RelocFormat = iota + 1

	// RelocScattered is struct scattered_relocation_info, used when the
	// referenced address has no symbol to name it. The R_SCATTERED bit
	// distinguishes the two forms.
	RelocScattered
)

// R_SCATTERED is set in the first word of a scattered relocation entry.
const R_SCATTERED uint32 = 0x80000000

// RelocLength is the log2 byte width of the field a relocation writes.
type RelocLength uint8

const (
	RelocByte  RelocLength = 0 // 1 byte
	RelocWord  RelocLength = 1 // 2 bytes
	RelocLong  RelocLength = 2 // 4 bytes
	RelocQuad  RelocLength = 3 // 8 bytes
)

// Bytes returns the field width in bytes.
func (l RelocLength) Bytes() int { return 1 << (l & 3) }

// RelocInfo is the decoded form of struct relocation_info.
//
// This type is the shared vocabulary; the actual byte-level decode and encode
// live in internal/format, which is the only place that knows the field
// offsets. Type is left as a uint8 because its meaning is per-architecture:
// interpret it with ARM64Reloc or X86_64Reloc according to the file's cputype.
type RelocInfo struct {
	Address   int32       // r_address: offset within the section
	SymbolNum uint32      // r_symbolnum: symbol index, or section ordinal if !Extern
	PCRel     bool        // r_pcrel
	Length    RelocLength // r_length
	Extern    bool        // r_extern
	Type      uint8       // r_type
}

// PackRelocWord builds the second word of a relocation_info entry.
//
// The layout is symbolnum:24, pcrel:1, length:2, extern:1, type:4 — note that
// extern sits at bit 27, between length and type, which is easy to get wrong
// when reading the shift-based construction in assembler sources.
func PackRelocWord(r RelocInfo) uint32 {
	w := r.SymbolNum & 0x00ffffff
	if r.PCRel {
		w |= 1 << 24
	}
	w |= uint32(r.Length&3) << 25
	if r.Extern {
		w |= 1 << 27
	}
	w |= uint32(r.Type&0x0f) << 28
	return w
}

// UnpackRelocWord decodes the second word of a relocation_info entry.
func UnpackRelocWord(w uint32) RelocInfo {
	return RelocInfo{
		SymbolNum: w & 0x00ffffff,
		PCRel:     w&(1<<24) != 0,
		Length:    RelocLength((w >> 25) & 3),
		Extern:    w&(1<<27) != 0,
		Type:      uint8((w >> 28) & 0x0f),
	}
}

// ScatteredInfo is the decoded form of struct scattered_relocation_info.
type ScatteredInfo struct {
	Address uint32      // r_address, 24 bits
	Type    uint8       // r_type, 4 bits
	Length  RelocLength // r_length
	PCRel   bool        // r_pcrel
	Value   int32       // r_value
}

// IsScattered reports whether the first word of a relocation entry indicates
// the scattered form. The word must already be in host order.
func IsScattered(word0 uint32) bool { return word0&R_SCATTERED != 0 }