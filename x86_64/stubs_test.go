package x86_64

import (
	"encoding/binary"
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
)

func imageRelocOf(typ macho.X86_64Reloc, length macho.RelocLength) image.Reloc {
	return image.Reloc{Type: uint8(typ), Length: length}
}

// decodeDisp32 independently reads a little-endian 32-bit signed
// RIP-relative displacement out of buf at the given field offset and resolves
// it against the instruction's own end address (bufAddr+fieldOff+4).
func decodeDisp32(buf []byte, bufAddr uint64, fieldOff int) uint64 {
	disp := int32(binary.LittleEndian.Uint32(buf[fieldOff:]))
	rip := bufAddr + uint64(fieldOff) + DispSize
	return uint64(int64(rip) + int64(disp))
}

func TestWriteGotSlot(t *testing.T) {
	b := New(backend.StubNonLazy)
	dst := make([]byte, 8)
	if err := b.WriteGotSlot(dst, 0x1122334455667788); err != nil {
		t.Fatalf("WriteGotSlot: %v", err)
	}
	if got := binary.LittleEndian.Uint64(dst); got != 0x1122334455667788 {
		t.Errorf("GOT slot = %#x, want %#x", got, 0x1122334455667788)
	}
	if err := b.WriteGotSlot(make([]byte, 4), 1); err == nil {
		t.Error("WriteGotSlot into a too-small buffer should fail")
	}
}

func TestWriteStub(t *testing.T) {
	b := New(backend.StubNonLazy)
	cases := []struct{ stubAddr, pointerAddr uint64 }{
		{0x100001000, 0x100004000},
		{0x100004000, 0x100001000}, // backward
		{0x100001000, 0x180000000}, // near the edge of what a 32-bit disp reaches, but well within
	}
	for _, c := range cases {
		dst := make([]byte, StubSize)
		if err := b.WriteStub(dst, c.stubAddr, c.pointerAddr); err != nil {
			t.Fatalf("WriteStub(%#x, %#x): %v", c.stubAddr, c.pointerAddr, err)
		}
		if dst[0] != 0xff || dst[1] != 0x25 {
			t.Fatalf("stub opcode bytes = %02x %02x, want ff 25 (jmpq *disp(%%rip))", dst[0], dst[1])
		}
		if got := decodeDisp32(dst, c.stubAddr, 2); got != c.pointerAddr {
			t.Errorf("WriteStub(%#x, %#x): decoded pointer address %#x", c.stubAddr, c.pointerAddr, got)
		}
	}

	// A displacement that does not fit 32 bits must be rejected rather than
	// silently truncated.
	dst := make([]byte, StubSize)
	if err := b.WriteStub(dst, 0, 1<<40); err == nil {
		t.Error("WriteStub with an out-of-range displacement should fail")
	}
}

func TestLazyStubHelper(t *testing.T) {
	b := New(backend.StubLazy)
	if !b.StubShape().Kind.Lazy() {
		t.Fatal("test setup error: backend should be configured for lazy stubs")
	}

	headerAddr := uint64(0x100001000)
	dyldPrivateAddr := uint64(0x100002000)
	binderGotAddr := uint64(0x100003008)

	header := make([]byte, StubHelperHeaderSize)
	if err := b.WriteStubHelperHeader(header, headerAddr, dyldPrivateAddr, binderGotAddr); err != nil {
		t.Fatalf("WriteStubHelperHeader: %v", err)
	}
	if header[0] != 0x4c || header[1] != 0x8d || header[2] != 0x1d {
		t.Fatalf("lea opcode bytes wrong: %02x %02x %02x", header[0], header[1], header[2])
	}
	if got := decodeDisp32(header, headerAddr, 3); got != dyldPrivateAddr {
		t.Errorf("decoded dyld_private address %#x, want %#x", got, dyldPrivateAddr)
	}
	if header[7] != 0x41 || header[8] != 0x53 {
		t.Errorf("pushq %%r11 bytes wrong: %02x %02x", header[7], header[8])
	}
	if header[9] != 0xff || header[10] != 0x25 {
		t.Fatalf("jmpq opcode bytes wrong: %02x %02x", header[9], header[10])
	}
	if got := decodeDisp32(header, headerAddr, 11); got != binderGotAddr {
		t.Errorf("decoded binder GOT address %#x, want %#x", got, binderGotAddr)
	}
	if header[15] != 0x90 {
		t.Errorf("trailing byte = %#x, want a nop (0x90)", header[15])
	}

	entryAddr := uint64(0x100001020)
	const lazyBindOff = uint32(0x55)
	entry := make([]byte, StubHelperEntrySize)
	if err := b.WriteStubHelperEntry(entry, entryAddr, headerAddr, lazyBindOff); err != nil {
		t.Fatalf("WriteStubHelperEntry: %v", err)
	}
	if entry[0] != 0x68 {
		t.Fatalf("push opcode = %#x, want 0x68 (pushq imm32)", entry[0])
	}
	if got := binary.LittleEndian.Uint32(entry[1:]); got != lazyBindOff {
		t.Errorf("pushed immediate = %#x, want %#x", got, lazyBindOff)
	}
	if entry[5] != 0xe9 {
		t.Fatalf("jmp opcode = %#x, want 0xe9 (jmp rel32)", entry[5])
	}
	if got := decodeDisp32(entry, entryAddr, 6); got != headerAddr {
		t.Errorf("decoded jmp target %#x, want header at %#x", got, headerAddr)
	}

	nonLazy := New(backend.StubNonLazy)
	if err := nonLazy.WriteStubHelperHeader(header, headerAddr, dyldPrivateAddr, binderGotAddr); err == nil {
		t.Error("WriteStubHelperHeader on a non-lazy backend should fail")
	}
	if err := nonLazy.WriteStubHelperEntry(entry, entryAddr, headerAddr, lazyBindOff); err == nil {
		t.Error("WriteStubHelperEntry on a non-lazy backend should fail")
	}
}

func TestClassifyRelocationTypes(t *testing.T) {
	b := New(backend.StubNonLazy)
	cases := []struct {
		typ  macho.X86_64Reloc
		want backend.Kind
	}{
		{macho.X86_64_RELOC_UNSIGNED, backend.KindAbsolute},
		{macho.X86_64_RELOC_SUBTRACTOR, backend.KindSubtractor},
		{macho.X86_64_RELOC_BRANCH, backend.KindBranch},
		{macho.X86_64_RELOC_SIGNED, backend.KindSigned},
		{macho.X86_64_RELOC_SIGNED_1, backend.KindSigned},
		{macho.X86_64_RELOC_SIGNED_2, backend.KindSigned},
		{macho.X86_64_RELOC_SIGNED_4, backend.KindSigned},
		{macho.X86_64_RELOC_GOT_LOAD, backend.KindGOTLoad},
		{macho.X86_64_RELOC_GOT, backend.KindGOT},
		{macho.X86_64_RELOC_TLV, backend.KindTLV},
	}
	for _, c := range cases {
		if got := b.Classify(uint8(c.typ)); got != c.want {
			t.Errorf("Classify(%v) = %v, want %v", c.typ, got, c.want)
		}
	}
	if got := b.Classify(0xff); got != backend.KindUnknown {
		t.Errorf("Classify(unknown) = %v, want KindUnknown", got)
	}
}

func TestPCRelBias(t *testing.T) {
	cases := []struct {
		typ  macho.X86_64Reloc
		want int
	}{
		{macho.X86_64_RELOC_SIGNED, 0},
		{macho.X86_64_RELOC_SIGNED_1, 1},
		{macho.X86_64_RELOC_SIGNED_2, 2},
		{macho.X86_64_RELOC_SIGNED_4, 4},
		{macho.X86_64_RELOC_BRANCH, 0},
	}
	for _, c := range cases {
		if got := PCRelBias(uint8(c.typ)); got != c.want {
			t.Errorf("PCRelBias(%v) = %d, want %d", c.typ, got, c.want)
		}
	}
}

func TestAddendRecovery(t *testing.T) {
	b := New(backend.StubNonLazy)

	buf32 := make([]byte, 4)
	var neg int32 = -123
	binary.LittleEndian.PutUint32(buf32, uint32(neg))
	v, ok := b.Addend(buf32, 0, imageRelocOf(macho.X86_64_RELOC_SIGNED, macho.RelocLong))
	if !ok || v != -123 {
		t.Errorf("Addend(32-bit signed) = %d,%v, want -123,true", v, ok)
	}

	buf64 := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf64, 0x1122334455667788)
	v, ok = b.Addend(buf64, 0, imageRelocOf(macho.X86_64_RELOC_UNSIGNED, macho.RelocQuad))
	if !ok || uint64(v) != 0x1122334455667788 {
		t.Errorf("Addend(64-bit) = %#x,%v, want %#x,true", v, ok, uint64(0x1122334455667788))
	}

	if _, ok := b.Addend(buf32, 0, imageRelocOf(0xff, macho.RelocLong)); ok {
		t.Error("Addend on an unclassifiable r_type should report ok=false")
	}
	if _, ok := b.Addend(buf32, 10, imageRelocOf(macho.X86_64_RELOC_SIGNED, macho.RelocLong)); ok {
		t.Error("Addend reading past the end of content should report ok=false")
	}
}
