package arm64

import (
	"fmt"

	"github.com/vertex-language/macho/backend"
)

// Instruction encoding for the immediate fields the linker fills in.
//
// Every function here takes the instruction the compiler emitted and returns
// it with one immediate field replaced. That is the contract the format
// assumes: an object file contains the opcode, the registers, and the
// addressing mode already correct, with the immediate zeroed, and the linker
// ORs in a value. Rebuilding the whole instruction instead would mean knowing
// which registers the compiler chose, which the relocation does not say.

// InsnSize is the width of one AArch64 instruction. Every instruction is
// exactly this wide, which is what makes a 26-bit branch field reach 28 bits.
const InsnSize = 4

// AdrpPageSize is the granule ADRP works in.
//
// It is 4096 and it is not the platform page size. arm64 macOS maps at 16 KiB,
// but ADRP's page is architectural: the instruction computes a 4 KiB-aligned
// address and the low twelve bits are supplied separately. Using the mapping
// page size here would discard two bits of the page delta and produce an
// address up to 12 KiB wrong.
const AdrpPageSize = 4096

// pageOf returns the 4 KiB page an address lies in.
func pageOf(addr uint64) uint64 { return addr &^ (AdrpPageSize - 1) }

// bitField extracts width bits starting at right from value and returns them
// positioned at left.
func bitField(value uint64, right, width, left uint) uint32 {
	return uint32(((value >> right) & ((1 << width) - 1)) << left)
}

// fitsSigned reports whether v fits a two's complement field of the given
// width.
func fitsSigned(v int64, bits uint) bool {
	if bits >= 64 {
		return true
	}
	lo := -(int64(1) << (bits - 1))
	hi := (int64(1) << (bits - 1)) - 1
	return v >= lo && v <= hi
}

// encodeBranch26 fills in the imm26 field of a B or BL.
//
//	25                                                            0
//	+-----------+---------------------------------------------------+
//	|           |                      imm26                        |
//	+-----------+---------------------------------------------------+
//
// delta is the byte displacement from the branch to its target. The low two
// bits are dropped because every instruction is 4-byte aligned, which is what
// turns 26 encoded bits into 28 bits of reach.
func encodeBranch26(base uint32, delta int64) (uint32, error) {
	if delta%InsnSize != 0 {
		return 0, fmt.Errorf("arm64: branch displacement %d is not a multiple of %d",
			delta, InsnSize)
	}
	if !fitsSigned(delta, 28) {
		return 0, &backend.RangeError{Value: delta, Bits: 26, Signed: true, Shift: 2}
	}
	return base | bitField(uint64(delta), 2, 26, 0), nil
}

// encodePage21 fills in the immhi/immlo fields of an ADRP.
//
//	  30 29    23                                       5
//	+-+---+------+----------------------------------------+---------+
//	| |ilo|      |                 immhi                  |         |
//	+-+---+------+----------------------------------------+---------+
//
// The two halves are not adjacent and are not in order: immlo holds bits 13:12
// of the byte delta at instruction bits 30:29, and immhi holds bits 32:14 at
// instruction bits 23:5. Together they are a 21-bit signed page count.
//
// delta is the difference between the target's page and the instruction's
// page, in bytes, so it is always a multiple of 4096.
//
// The range check is on the exact bound — a 21-bit signed page count scaled by
// 4096 reaches ±2^32 — rather than the looser 35-bit check lld uses. Being
// stricter here can only reject a displacement that would have encoded
// wrongly.
func encodePage21(base uint32, delta int64) (uint32, error) {
	if delta%AdrpPageSize != 0 {
		return 0, fmt.Errorf("arm64: page delta %d is not a multiple of %d",
			delta, AdrpPageSize)
	}
	if !fitsSigned(delta, 33) {
		return 0, &backend.RangeError{Value: delta, Bits: 21, Signed: true, Shift: 12}
	}
	v := uint64(delta)
	return base | bitField(v, 12, 2, 29) | bitField(v, 14, 19, 5), nil
}

// encodePageOff12 fills in the imm12 field of an ADD or a load/store.
//
//	          21                      10
//	+-------------------+-----------------------+-------------------+
//	|                   |         imm12         |                   |
//	+-------------------+-----------------------+-------------------+
//
// The immediate is scaled by the access size, so the same twelve bits mean a
// different number of bytes depending on the instruction they land in. An ADD
// takes a raw byte offset; an LDR of a doubleword takes the offset divided by
// eight. Writing the unscaled value into a load produces an address off by a
// factor of the access width, which links cleanly and reads the wrong memory.
//
// va is the target's full address; only its low twelve bits are used, and the
// caller has already supplied the high bits through the paired ADRP.
func encodePageOff12(base uint32, va uint64) (uint32, error) {
	scale := loadStoreScale(base)
	size := uint64(1) << scale
	if va&(size-1) != 0 {
		return 0, fmt.Errorf("arm64: %d-bit load/store of 0x%x is not %d-byte aligned",
			8*size, va, size)
	}
	return base | bitField(va, scale, 12-scale, 10), nil
}

// loadStoreScale returns the log2 access size an instruction's imm12 is scaled
// by, or zero for anything that is not a scaled load or store.
//
// An ADD immediate is unscaled and falls out of here as zero, which is the
// right answer for it.
func loadStoreScale(insn uint32) uint {
	// Load/store register, unsigned immediate offset.
	if insn&0x3b000000 != 0x39000000 {
		return 0
	}
	scale := uint(insn >> 30)
	// The 128-bit SIMD variant encodes size as 0 with the opc high bit set,
	// so a naive read of bits 31:30 says "one byte" for a sixteen-byte access.
	// This is the case that is easiest to get wrong and hardest to notice: it
	// only misencodes for offsets that are not 16-byte aligned.
	if scale == 0 && insn&0x04800000 == 0x04800000 {
		scale = 4
	}
	return scale
}

// isLdrImmediate reports whether an instruction is an LDR with an unsigned
// immediate offset, in either the 32- or 64-bit general-register form.
//
// This is the check a GOT-load relaxation must pass before rewriting the
// instruction: the relaxation turns an LDR into an ADD by replacing the
// opcode, and doing that to anything else produces a valid instruction that
// does something unrelated.
//
// Nothing calls this yet. GOT loads are not relaxed — see the package comment
// — and it is here so that when they are, the check is already written down
// rather than reinvented.
func isLdrImmediate(insn uint32) bool { return insn&0xbfc00000 == 0xb9400000 }

// relaxGotLoadToAdd rewrites an LDR through a GOT slot into an ADD of the
// symbol's own address, for a symbol that turned out to be defined in this
// image.
//
//	adrp x0, _foo@GOTPAGE      adrp x0, _foo@PAGE
//	ldr  x0, [x0, _foo@GOTPAGEOFF]  ->  add x0, x0, _foo@PAGEOFF
//
// The register fields and the destination survive in the low 21 bits; only the
// opcode changes. Unused for now, for the same reason as isLdrImmediate.
func relaxGotLoadToAdd(insn uint32) (uint32, error) {
	if !isLdrImmediate(insn) {
		return 0, fmt.Errorf("arm64: GOT load relaxation needs an LDR, got 0x%08x", insn)
	}
	if (insn>>10)&0xfff != 0 {
		return 0, fmt.Errorf("arm64: GOT load 0x%08x has a nonzero embedded immediate", insn)
	}
	return (insn & 0x001fffff) | 0x91000000, nil
}