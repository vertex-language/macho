package arm64

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/macho/backend"
)

// Stub, GOT, and lazy-binding code sequences.
//
// Each sequence below is the instruction stream with its immediate fields
// zeroed, exactly as an object file would carry it. The write functions fill
// the immediates in, which means the same encoders that apply relocations from
// input objects also build the linker's own content — a stub is not a special
// case in the encoder, only in who produced the bytes.

// Sizes, in bytes.
const (
	// StubSize is one __stubs entry: adrp, ldr, br.
	StubSize = 12

	// ThunkSize is one range-extension thunk: adrp, add, br.
	ThunkSize = 12

	// StubHelperHeaderSize is the one-per-image __stub_helper prologue.
	StubHelperHeaderSize = 24

	// StubHelperEntrySize is one per-symbol __stub_helper trampoline.
	StubHelperEntrySize = 12
)

// stubCode is the non-lazy and lazy stub body. It loads a pointer and jumps
// through it; which table the pointer lives in is the only difference between
// the two strategies, and that is decided by the address the caller passes.
//
//	adrp x16, <ptr>@page
//	ldr  x16, [x16, <ptr>@pageoff]
//	br   x16
var stubCode = [3]uint32{0x90000010, 0xf9400210, 0xd61f0200}

// stubHelperHeaderCode is the prologue every lazy image has exactly one of. It
// pushes the image's dyld_private cookie alongside the symbol index the entry
// left in x16, then jumps through the GOT to dyld_stub_binder.
//
//	adrp x17, <dyld_private>@page
//	add  x17, x17, <dyld_private>@pageoff
//	stp  x16, x17, [sp, #-16]!
//	adrp x16, <dyld_stub_binder@got>@page
//	ldr  x16, [x16, <dyld_stub_binder@got>@pageoff]
//	br   x16
var stubHelperHeaderCode = [6]uint32{
	0x90000011, 0x91000231, 0xa9bf47f0,
	0x90000010, 0xf9400210, 0xd61f0200,
}

// stubHelperEntryCode is one per lazily bound symbol. The literal load reaches
// the word at the end of the entry, which holds this symbol's offset into the
// lazy bind opcode stream — the argument dyld_stub_binder needs to know which
// symbol to resolve.
//
//	ldr w16, l0
//	b   <header>
//	l0: .long <lazy bind offset>
var stubHelperEntryCode = [3]uint32{0x18000050, 0x14000000, 0x00000000}

// GotShape implements backend.Stubber.
func (b *Backend) GotShape() backend.GotShape { return b.got }

// StubShape implements backend.Stubber.
func (b *Backend) StubShape() backend.StubShape { return b.stub }

// WriteGotSlot writes one GOT entry.
//
// The value written is the target's address. Under chained fixups dyld
// overwrites it, and the bytes here are the chain entry rather than a usable
// pointer — but the encoder produces those from the fixup records, and this
// still writes the address so that a non-chained image and a golden diff both
// see something meaningful.
func (b *Backend) WriteGotSlot(dst []byte, target uint64) error {
	if len(dst) < b.cfg.WordSize {
		return fmt.Errorf("arm64: GOT slot needs %d bytes, got %d", b.cfg.WordSize, len(dst))
	}
	if b.cfg.WordSize == 4 {
		if target > 0xffffffff {
			return &backend.RangeError{
				Reloc: "GOT slot", Value: int64(target), Bits: 32,
			}
		}
		binary.LittleEndian.PutUint32(dst, uint32(target))
		return nil
	}
	binary.LittleEndian.PutUint64(dst, target)
	return nil
}

// WriteStub writes one __stubs entry.
//
// pointerAddr is the slot the stub loads through: a __got entry for a non-lazy
// stub, a __la_symbol_ptr entry for a lazy one. The stub itself is identical
// either way, which is why one function serves both.
func (b *Backend) WriteStub(dst []byte, stubAddr, pointerAddr uint64) error {
	if len(dst) < StubSize {
		return fmt.Errorf("arm64: stub needs %d bytes, got %d", StubSize, len(dst))
	}
	adrp, err := encodePage21(stubCode[0], int64(pageOf(pointerAddr))-int64(pageOf(stubAddr)))
	if err != nil {
		return stubErr("stub", err)
	}
	ldr, err := encodePageOff12(stubCode[1], pointerAddr)
	if err != nil {
		return stubErr("stub", err)
	}
	put32(dst, 0, adrp)
	put32(dst, 1, ldr)
	put32(dst, 2, stubCode[2])
	return nil
}

// WriteStubHelperHeader writes the one-per-image lazy binding prologue.
func (b *Backend) WriteStubHelperHeader(dst []byte, headerAddr, dyldPrivateAddr, binderGotAddr uint64) error {
	if !b.stub.Kind.Lazy() {
		return fmt.Errorf("arm64: this backend uses %v stubs and has no stub helper", b.stub.Kind)
	}
	if len(dst) < StubHelperHeaderSize {
		return fmt.Errorf("arm64: stub helper header needs %d bytes, got %d",
			StubHelperHeaderSize, len(dst))
	}
	// Each ADRP measures from its own address, not from the start of the
	// header, which is why the pc for word 3 is headerAddr+12.
	adrp0, err := encodePage21(stubHelperHeaderCode[0],
		int64(pageOf(dyldPrivateAddr))-int64(pageOf(headerAddr)))
	if err != nil {
		return stubErr("stub helper header", err)
	}
	add1, err := encodePageOff12(stubHelperHeaderCode[1], dyldPrivateAddr)
	if err != nil {
		return stubErr("stub helper header", err)
	}
	adrp3, err := encodePage21(stubHelperHeaderCode[3],
		int64(pageOf(binderGotAddr))-int64(pageOf(headerAddr+3*InsnSize)))
	if err != nil {
		return stubErr("stub helper header", err)
	}
	ldr4, err := encodePageOff12(stubHelperHeaderCode[4], binderGotAddr)
	if err != nil {
		return stubErr("stub helper header", err)
	}
	put32(dst, 0, adrp0)
	put32(dst, 1, add1)
	put32(dst, 2, stubHelperHeaderCode[2])
	put32(dst, 3, adrp3)
	put32(dst, 4, ldr4)
	put32(dst, 5, stubHelperHeaderCode[5])
	return nil
}

// WriteStubHelperEntry writes one per-symbol lazy binding trampoline.
//
// lazyBindOff is stored as a plain word at the end of the entry rather than
// encoded into an instruction, which is what the literal load in word 0
// reaches. It is the byte offset of this symbol's opcodes in the lazy bind
// stream.
func (b *Backend) WriteStubHelperEntry(dst []byte, entryAddr, headerAddr uint64, lazyBindOff uint32) error {
	if !b.stub.Kind.Lazy() {
		return fmt.Errorf("arm64: this backend uses %v stubs and has no stub helper", b.stub.Kind)
	}
	if len(dst) < StubHelperEntrySize {
		return fmt.Errorf("arm64: stub helper entry needs %d bytes, got %d",
			StubHelperEntrySize, len(dst))
	}
	// The branch is word 1, so its pc is one instruction past the entry.
	br, err := encodeBranch26(stubHelperEntryCode[1],
		int64(headerAddr)-int64(entryAddr+InsnSize))
	if err != nil {
		return stubErr("stub helper entry", err)
	}
	put32(dst, 0, stubHelperEntryCode[0])
	put32(dst, 1, br)
	put32(dst, 2, lazyBindOff)
	return nil
}

func put32(dst []byte, word int, v uint32) {
	binary.LittleEndian.PutUint32(dst[word*InsnSize:], v)
}

// stubErr names the synthesized content a range failure came from. Linker
// content has no input file and no atom, so a bare RangeError would report a
// blank location.
func stubErr(what string, err error) error {
	if re, ok := err.(*backend.RangeError); ok {
		re.Reloc = what
		re.Atom = "<linker-generated " + what + ">"
		return re
	}
	return fmt.Errorf("arm64: %s: %w", what, err)
}