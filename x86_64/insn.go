package x86_64

import (
	"encoding/binary"
	"fmt"
)

// Instruction-level helpers.
//
// There is far less to do here than on arm64. x86_64 has no split
// page/page-offset addressing and no scaled immediates: a RIP-relative
// reference is a flat signed 32-bit displacement in the last four bytes of the
// instruction, so filling one in is a single little-endian store. What this
// file holds is the RIP arithmetic and the one instruction rewrite the
// architecture supports.

// putRIPRelative writes a RIP-relative displacement into a synthesized
// instruction sequence.
//
// buf is the whole sequence, bufAddr the virtual address of buf[0], and next
// the offset within buf of the instruction *after* the one being patched —
// which is where RIP points when the instruction executes. The displacement
// field is always the four bytes immediately before that.
//
// Passing the offset of the next instruction rather than of the field is
// deliberate: it is the quantity that is actually meaningful, and it makes the
// call sites read as the instruction boundaries they are.
func putRIPRelative(buf []byte, bufAddr uint64, next int, dest uint64) error {
	if next < DispSize || next > len(buf) {
		return fmt.Errorf("x86_64: displacement at %d does not lie in a %d-byte sequence",
			next, len(buf))
	}
	rip := bufAddr + uint64(next)
	d := int64(dest) - int64(rip)
	if d < -(1<<31) || d > (1<<31)-1 {
		return fmt.Errorf("x86_64: displacement %d from 0x%x to 0x%x does not fit 32 bits",
			d, rip, dest)
	}
	binary.LittleEndian.PutUint32(buf[next-DispSize:], uint32(int32(d)))
	return nil
}

// Opcode bytes for the one relaxation this architecture offers.
const (
	// opMovRegMem is the ModRM-form MOV that loads a register from memory:
	// the opcode byte of `movq foo@GOTPCREL(%rip), %reg`.
	opMovRegMem = 0x8b

	// opLea is LEA, which computes an address instead of loading through it.
	opLea = 0x8d
)

// relaxGotLoad rewrites a load through the GOT into a direct address
// computation, for a symbol that turned out to be defined in this image.
//
//	movq _foo@GOTPCREL(%rip), %rax   ->   leaq _foo(%rip), %rax
//
// The two instructions have identical encodings apart from the opcode byte, so
// the ModRM byte, the REX prefix, and the destination register all survive
// untouched. loc is the offset of the displacement field; the opcode sits two
// bytes before it, past the ModRM byte.
//
// Nothing calls this yet — every GOT_LOAD gets a slot, as in the arm64
// backend, because deciding otherwise requires Scan to predict before layout
// which slots will survive. It is written down here so the instruction check
// exists when the relaxation is turned on, rather than being reconstructed.
func relaxGotLoad(buf []byte, loc int) error {
	if loc < 2 || loc > len(buf) {
		return fmt.Errorf("x86_64: GOT load at %d has no room for an opcode", loc)
	}
	if buf[loc-2] != opMovRegMem {
		return fmt.Errorf("x86_64: GOT load relaxation needs a MOV, found opcode 0x%02x",
			buf[loc-2])
	}
	buf[loc-2] = opLea
	return nil
}