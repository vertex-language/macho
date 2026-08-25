package x86_64

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/macho/backend"
)

// Sizes, in bytes.
const (
	// StubSize is one __stubs entry: a six-byte indirect jump.
	StubSize = 6

	// StubHelperHeaderSize is the one-per-image __stub_helper prologue.
	StubHelperHeaderSize = 16

	// StubHelperEntrySize is one per-symbol __stub_helper trampoline.
	StubHelperEntrySize = 10
)

// stubCode is the stub body, with its displacement zeroed.
//
//	jmpq *<ptr>(%rip)
//
// Six bytes, and that is the whole stub — there is no scratch register to load
// through, because an indirect jump can take a memory operand. The arm64
// equivalent needs three instructions and twelve bytes to say the same thing.
var stubCode = [StubSize]byte{0xff, 0x25, 0, 0, 0, 0}

// stubHelperHeaderCode is the prologue every lazy image has exactly one of.
//
//	0x0: leaq <dyld_private>(%rip), %r11
//	0x7: pushq %r11
//	0x9: jmpq *<dyld_stub_binder@got>(%rip)
//	0xf: nop
//
// The trailing NOP is padding to sixteen bytes, not an instruction anything
// executes: the jump above it never returns.
var stubHelperHeaderCode = [StubHelperHeaderSize]byte{
	0x4c, 0x8d, 0x1d, 0, 0, 0, 0,
	0x41, 0x53,
	0xff, 0x25, 0, 0, 0, 0,
	0x90,
}

// stubHelperEntryCode is one per lazily bound symbol.
//
//	0x0: pushq $<lazy bind offset>
//	0x5: jmp <__stub_helper>
//
// The pushed value is this symbol's byte offset into the lazy bind opcode
// stream — the argument dyld_stub_binder uses to find out which symbol to
// resolve. It is an immediate here rather than a literal load, which is why
// this entry is ten bytes to arm64's twelve.
var stubHelperEntryCode = [StubHelperEntrySize]byte{
	0x68, 0, 0, 0, 0,
	0xe9, 0, 0, 0, 0,
}

// GotShape implements backend.Stubber.
func (b *Backend) GotShape() backend.GotShape { return b.got }

// StubShape implements backend.Stubber.
func (b *Backend) StubShape() backend.StubShape { return b.stub }

// WriteGotSlot writes one GOT entry.
func (b *Backend) WriteGotSlot(dst []byte, target uint64) error {
	if len(dst) < 8 {
		return fmt.Errorf("x86_64: GOT slot needs 8 bytes, got %d", len(dst))
	}
	binary.LittleEndian.PutUint64(dst, target)
	return nil
}

// WriteStub writes one __stubs entry.
//
// pointerAddr is the slot the stub jumps through: a __got entry for a non-lazy
// stub, a __la_symbol_ptr entry for a lazy one.
func (b *Backend) WriteStub(dst []byte, stubAddr, pointerAddr uint64) error {
	if len(dst) < StubSize {
		return fmt.Errorf("x86_64: stub needs %d bytes, got %d", StubSize, len(dst))
	}
	copy(dst, stubCode[:])
	// The displacement runs to the end of the stub, so RIP is the stub's own
	// end address.
	if err := putRIPRelative(dst[:StubSize], stubAddr, StubSize, pointerAddr); err != nil {
		return stubErr("stub", err)
	}
	return nil
}

// WriteStubHelperHeader writes the one-per-image lazy binding prologue.
func (b *Backend) WriteStubHelperHeader(dst []byte, headerAddr, dyldPrivateAddr, binderGotAddr uint64) error {
	if !b.stubs.Lazy() {
		return fmt.Errorf("x86_64: this backend uses %v stubs and has no stub helper", b.stubs)
	}
	if len(dst) < StubHelperHeaderSize {
		return fmt.Errorf("x86_64: stub helper header needs %d bytes, got %d",
			StubHelperHeaderSize, len(dst))
	}
	copy(dst, stubHelperHeaderCode[:])
	// The LEA ends at 0x7 and the JMP at 0xf; each displacement is measured
	// from the end of its own instruction.
	if err := putRIPRelative(dst[:StubHelperHeaderSize], headerAddr, 0x7, dyldPrivateAddr); err != nil {
		return stubErr("stub helper header", err)
	}
	if err := putRIPRelative(dst[:StubHelperHeaderSize], headerAddr, 0xf, binderGotAddr); err != nil {
		return stubErr("stub helper header", err)
	}
	return nil
}

// WriteStubHelperEntry writes one per-symbol lazy binding trampoline.
func (b *Backend) WriteStubHelperEntry(dst []byte, entryAddr, headerAddr uint64, lazyBindOff uint32) error {
	if !b.stubs.Lazy() {
		return fmt.Errorf("x86_64: this backend uses %v stubs and has no stub helper", b.stubs)
	}
	if len(dst) < StubHelperEntrySize {
		return fmt.Errorf("x86_64: stub helper entry needs %d bytes, got %d",
			StubHelperEntrySize, len(dst))
	}
	copy(dst, stubHelperEntryCode[:])
	// The PUSH's immediate is an absolute value, not a displacement, so it is
	// written directly rather than through the RIP helper.
	binary.LittleEndian.PutUint32(dst[1:], lazyBindOff)
	if err := putRIPRelative(dst[:StubHelperEntrySize], entryAddr, StubHelperEntrySize, headerAddr); err != nil {
		return stubErr("stub helper entry", err)
	}
	return nil
}

// stubErr names the synthesized content a failure came from. Linker-generated
// bytes have no input file and no atom, so an undecorated error would report a
// blank location.
func stubErr(what string, err error) error {
	return fmt.Errorf("x86_64: <linker-generated %s>: %w", what, err)
}