package arm64

import (
	"encoding/binary"
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
)

// The decoders below are written independently from insn.go's encoders,
// straight from the ARMv8 instruction encoding tables, so that a test built
// from them can catch a bug shared between an encoder and a same-package
// helper it might otherwise be tempted to reuse.

// decodeADRP returns the page delta (in bytes, a multiple of 4096) an ADRP
// instruction encodes.
func decodeADRP(insn uint32) int64 {
	immlo := uint64((insn >> 29) & 0x3)
	immhi := uint64((insn >> 5) & 0x7ffff)
	combined := (immhi << 2) | immlo // 21 bits
	// Sign-extend from 21 bits, then scale by the 4 KiB page granule. The
	// cast to int64 must happen before the right shift, or Go's logical
	// shift on the unsigned operand throws the sign bit away.
	shifted := int64(combined<<43) >> 43
	return shifted * 4096
}

// decodeAddImm12 returns an ADD (immediate)'s unscaled 12-bit immediate.
func decodeAddImm12(insn uint32) uint64 {
	return uint64((insn >> 10) & 0xfff)
}

// decodeLdrImm12 returns an LDR/STR (unsigned immediate)'s byte offset,
// scaled by the instruction's own access size.
func decodeLdrImm12(insn uint32) uint64 {
	imm12 := uint64((insn >> 10) & 0xfff)
	size := uint(insn >> 30) // 2 -> 4 bytes, 3 -> 8 bytes for the plain GP form
	return imm12 << size
}

// decodeBranch26 returns a B/BL's byte displacement.
func decodeBranch26(insn uint32) int64 {
	imm26 := uint64(insn & 0x3ffffff)
	// Sign-extend from 26 bits, then scale by the instruction width.
	shifted := int64(imm26<<38) >> 38
	return shifted * 4
}

func le32(b []byte, word int) uint32 { return binary.LittleEndian.Uint32(b[word*4:]) }

func TestEncodePage21RoundTrip(t *testing.T) {
	cases := []struct {
		insnAddr, target uint64
	}{
		{0x100000000, 0x100000000},                // same page
		{0x100000000, 0x100004000},                // forward, several pages
		{0x100010000, 0x100000000},                // backward
		{0x100000000, 0x100000000 + (1<<32 - 4096)}, // far forward, just inside range
		{0x1_00000000, 0x00000000},                // to address zero
	}
	for _, c := range cases {
		delta := int64(pageOf(c.target)) - int64(pageOf(c.insnAddr))
		insn, err := encodePage21(0x90000010, delta)
		if err != nil {
			t.Fatalf("encodePage21(%#x -> %#x): %v", c.insnAddr, c.target, err)
		}
		gotDelta := decodeADRP(insn)
		if gotDelta != delta {
			t.Errorf("insn=%#x -> %#x: decoded delta %d, want %d", c.insnAddr, c.target, gotDelta, delta)
		}
		gotPage := uint64(int64(pageOf(c.insnAddr)) + gotDelta)
		if gotPage != pageOf(c.target) {
			t.Errorf("insn=%#x -> %#x: reconstructed page %#x, want %#x",
				c.insnAddr, c.target, gotPage, pageOf(c.target))
		}
	}
}

func TestEncodePage21RangeCheck(t *testing.T) {
	// A 21-bit signed page count scaled by 4096 reaches exactly ±2^32.
	const maxReach = int64(1) << 32
	if _, err := encodePage21(0x90000010, maxReach-4096); err != nil {
		t.Errorf("delta just inside range failed: %v", err)
	}
	if _, err := encodePage21(0x90000010, -maxReach); err != nil {
		t.Errorf("delta just inside negative range failed: %v", err)
	}
	if _, err := encodePage21(0x90000010, maxReach); err == nil {
		t.Error("delta one page past the positive range should fail")
	}
	if _, err := encodePage21(0x90000010, -maxReach-4096); err == nil {
		t.Error("delta one page past the negative range should fail")
	}
	if _, err := encodePage21(0x90000010, 1); err == nil {
		t.Error("a delta that is not a multiple of 4096 should fail")
	}
}

func TestEncodeBranch26RoundTrip(t *testing.T) {
	for _, delta := range []int64{0, 4, -4, 1 << 20, -(1 << 20), (1 << 27) - 4, -(1 << 27)} {
		insn, err := encodeBranch26(0x94000000, delta)
		if err != nil {
			t.Fatalf("encodeBranch26(%d): %v", delta, err)
		}
		if got := decodeBranch26(insn); got != delta {
			t.Errorf("encodeBranch26(%d): decoded %d", delta, got)
		}
	}
	// ±128 MiB is the documented reach; one instruction beyond it must fail
	// in the (rarer) forward direction and succeed one instruction inside it
	// backward, matching the asymmetry backend.ThunkShape documents.
	const reach = int64(128) << 20
	if _, err := encodeBranch26(0x94000000, reach-4); err != nil {
		t.Errorf("delta at -Backward failed: %v", err)
	}
	if _, err := encodeBranch26(0x94000000, -reach); err != nil {
		t.Errorf("delta at -reach failed: %v", err)
	}
	if _, err := encodeBranch26(0x94000000, reach); err == nil {
		t.Error("delta of +reach should overflow the 28-bit signed field")
	}
	if _, err := encodeBranch26(0x94000000, 3); err == nil {
		t.Error("a non-4-byte-aligned displacement should fail")
	}
}

func TestEncodePageOff12ScalesByAccessSize(t *testing.T) {
	// An ADD does not scale.
	add, err := encodePageOff12(0x91000210, 0xabc)
	if err != nil {
		t.Fatalf("encodePageOff12(ADD): %v", err)
	}
	if got := decodeAddImm12(add); got != 0xabc {
		t.Errorf("ADD imm12 = %#x, want %#x", got, 0xabc)
	}

	// An LDR (64-bit GP form, size=3) scales by 8 and requires alignment.
	ldrBase := uint32(0xf9400210)
	ldr, err := encodePageOff12(ldrBase, 0x18)
	if err != nil {
		t.Fatalf("encodePageOff12(LDR, aligned): %v", err)
	}
	if got := decodeLdrImm12(ldr); got != 0x18 {
		t.Errorf("LDR byte offset = %#x, want %#x", got, 0x18)
	}
	if _, err := encodePageOff12(ldrBase, 0x1a); err == nil {
		t.Error("an LDR offset not aligned to the access size should fail")
	}
}

func TestWriteGotSlot(t *testing.T) {
	b := New(Config{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, WordSize: 8})
	dst := make([]byte, 8)
	if err := b.WriteGotSlot(dst, 0x1122334455667788); err != nil {
		t.Fatalf("WriteGotSlot: %v", err)
	}
	if got := binary.LittleEndian.Uint64(dst); got != 0x1122334455667788 {
		t.Errorf("GOT slot = %#x, want %#x", got, 0x1122334455667788)
	}

	if err := b.WriteGotSlot(make([]byte, 3), 1); err == nil {
		t.Error("WriteGotSlot into a too-small buffer should fail")
	}
}

// decodeStub independently reconstructs the pointer address a __stubs entry
// (adrp x16, ldr x16, br x16) loads through, given the stub's own address.
func decodeStub(t *testing.T, dst []byte, stubAddr uint64) uint64 {
	t.Helper()
	adrp, ldr, br := le32(dst, 0), le32(dst, 1), le32(dst, 2)
	if br != 0xd61f0200 {
		t.Fatalf("word 2 = %#x, want the fixed br x16 encoding 0xd61f0200", br)
	}
	page := uint64(int64(pageOf(stubAddr)) + decodeADRP(adrp))
	off := decodeLdrImm12(ldr)
	return page + off
}

func TestWriteStub(t *testing.T) {
	b := New(Config{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, WordSize: 8})
	cases := []struct{ stubAddr, pointerAddr uint64 }{
		{0x100004000, 0x100008000},
		{0x100008000, 0x100004000}, // backward
		{0x100004ff8, 0x100008008}, // crossing a page boundary right at the edge
	}
	for _, c := range cases {
		dst := make([]byte, StubSize)
		if err := b.WriteStub(dst, c.stubAddr, c.pointerAddr); err != nil {
			t.Fatalf("WriteStub(%#x, %#x): %v", c.stubAddr, c.pointerAddr, err)
		}
		if got := decodeStub(t, dst, c.stubAddr); got != c.pointerAddr {
			t.Errorf("WriteStub(%#x, %#x): decoded pointer address %#x", c.stubAddr, c.pointerAddr, got)
		}
	}
}

// decodeThunk independently reconstructs the target address a thunk (adrp
// x16, add x16, br x16) materializes.
func decodeThunk(t *testing.T, dst []byte, thunkAddr uint64) uint64 {
	t.Helper()
	adrp, add, br := le32(dst, 0), le32(dst, 1), le32(dst, 2)
	if br != 0xd61f0200 {
		t.Fatalf("word 2 = %#x, want the fixed br x16 encoding 0xd61f0200", br)
	}
	page := uint64(int64(pageOf(thunkAddr)) + decodeADRP(adrp))
	return page + decodeAddImm12(add)
}

func TestWriteThunk(t *testing.T) {
	b := New(Config{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, WordSize: 8})
	cases := []struct{ thunkAddr, target uint64 }{
		{0x100004000, 0x180000000},
		{0x180000000, 0x100004000},
		{0x100004000, 0x100004000 + 3*4}, // a thunk to just past itself
	}
	for _, c := range cases {
		dst := make([]byte, ThunkSize)
		if err := b.WriteThunk(dst, c.thunkAddr, c.target); err != nil {
			t.Fatalf("WriteThunk(%#x, %#x): %v", c.thunkAddr, c.target, err)
		}
		if got := decodeThunk(t, dst, c.thunkAddr); got != c.target {
			t.Errorf("WriteThunk(%#x -> %#x): decoded target %#x", c.thunkAddr, c.target, got)
		}
	}
}

// TestThunkReachesBeyondBranchRange is the property that makes Thunker
// meaningful: a target the ThunkShape says a plain BRANCH26 cannot reach must
// still be encodable by WriteThunk, since that is the entire point of a
// veneer.
func TestThunkReachesBeyondBranchRange(t *testing.T) {
	b := New(Config{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, WordSize: 8})
	thunkAddr := uint64(0x100000000)
	target := thunkAddr + uint64(BranchReach)*4 // far past a BRANCH26's reach

	shape := b.ThunkShape()
	if shape.InRange(thunkAddr, target) {
		t.Fatal("test setup error: target should be out of BRANCH26 range")
	}
	dst := make([]byte, ThunkSize)
	if err := b.WriteThunk(dst, thunkAddr, target); err != nil {
		t.Fatalf("WriteThunk to a far target: %v", err)
	}
	if got := decodeThunk(t, dst, thunkAddr); got != target {
		t.Errorf("decoded target %#x, want %#x", got, target)
	}
}

// TestLazyStubHelper exercises the lazy-binding path: a header that jumps
// through the GOT to dyld_stub_binder, and one per-symbol entry whose literal
// word carries its offset into the lazy bind opcode stream.
func TestLazyStubHelper(t *testing.T) {
	b := New(Config{
		CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL,
		WordSize: 8, Stubs: backend.StubLazy,
	})
	if !b.StubShape().Kind.Lazy() {
		t.Fatal("test setup error: backend should be configured for lazy stubs")
	}

	headerAddr := uint64(0x100004000)
	dyldPrivateAddr := uint64(0x100008000)
	binderGotAddr := uint64(0x10000c008)

	header := make([]byte, StubHelperHeaderSize)
	if err := b.WriteStubHelperHeader(header, headerAddr, dyldPrivateAddr, binderGotAddr); err != nil {
		t.Fatalf("WriteStubHelperHeader: %v", err)
	}
	adrp0, add1, stp2 := le32(header, 0), le32(header, 1), le32(header, 2)
	if stp2 != 0xa9bf47f0 {
		t.Errorf("word 2 = %#x, want the fixed stp encoding 0xa9bf47f0", stp2)
	}
	gotPriv := uint64(int64(pageOf(headerAddr))+decodeADRP(adrp0)) + decodeAddImm12(add1)
	if gotPriv != dyldPrivateAddr {
		t.Errorf("decoded dyld_private address %#x, want %#x", gotPriv, dyldPrivateAddr)
	}
	adrp3, ldr4, br5 := le32(header, 3), le32(header, 4), le32(header, 5)
	if br5 != 0xd61f0200 {
		t.Errorf("word 5 = %#x, want the fixed br x16 encoding", br5)
	}
	// Each ADRP measures from its own address: word 3 is 3 instructions past
	// headerAddr.
	gotBinderGot := uint64(int64(pageOf(headerAddr+3*InsnSize))+decodeADRP(adrp3)) + decodeLdrImm12(ldr4)
	if gotBinderGot != binderGotAddr {
		t.Errorf("decoded binder GOT address %#x, want %#x", gotBinderGot, binderGotAddr)
	}

	entryAddr := uint64(0x100004018)
	const lazyBindOff = uint32(0x2a)
	entry := make([]byte, StubHelperEntrySize)
	if err := b.WriteStubHelperEntry(entry, entryAddr, headerAddr, lazyBindOff); err != nil {
		t.Fatalf("WriteStubHelperEntry: %v", err)
	}
	ldrLit, br, lit := le32(entry, 0), le32(entry, 1), le32(entry, 2)
	if ldrLit != 0x18000050 {
		t.Errorf("word 0 = %#x, want the fixed ldr w16,l0 encoding 0x18000050", ldrLit)
	}
	if lit != lazyBindOff {
		t.Errorf("literal word = %#x, want %#x", lit, lazyBindOff)
	}
	// The branch's pc is one instruction past the entry.
	gotHeader := uint64(int64(entryAddr+InsnSize) + decodeBranch26(br))
	if gotHeader != headerAddr {
		t.Errorf("decoded branch target %#x, want header at %#x", gotHeader, headerAddr)
	}

	// A non-lazy backend has no stub helper at all.
	nonLazy := New(Config{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, WordSize: 8})
	if err := nonLazy.WriteStubHelperHeader(header, headerAddr, dyldPrivateAddr, binderGotAddr); err == nil {
		t.Error("WriteStubHelperHeader on a non-lazy backend should fail")
	}
	if err := nonLazy.WriteStubHelperEntry(entry, entryAddr, headerAddr, lazyBindOff); err == nil {
		t.Error("WriteStubHelperEntry on a non-lazy backend should fail")
	}
}

func TestClassifyRelocationTypes(t *testing.T) {
	b := New(Config{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, WordSize: 8})
	cases := []struct {
		typ  macho.ARM64Reloc
		want backend.Kind
	}{
		{macho.ARM64_RELOC_BRANCH26, backend.KindBranch},
		{macho.ARM64_RELOC_GOT_LOAD_PAGE21, backend.KindGOTLoad},
		{macho.ARM64_RELOC_GOT_LOAD_PAGEOFF12, backend.KindGOTLoad},
		{macho.ARM64_RELOC_UNSIGNED, backend.KindAbsolute},
	}
	for _, c := range cases {
		if got := b.Classify(uint8(c.typ)); got != c.want {
			t.Errorf("Classify(%v) = %v, want %v", c.typ, got, c.want)
		}
	}
	if got := b.Classify(0xff); got != backend.KindUnknown {
		t.Errorf("Classify(unknown type) = %v, want KindUnknown", got)
	}
}
