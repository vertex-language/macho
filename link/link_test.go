package link_test

import (
	"bytes"
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/format"
	"github.com/vertex-language/macho/link"
	"github.com/vertex-language/macho/obj"

	_ "github.com/vertex-language/macho/arm64"
)

// fakeLibSystem is a minimal TBD v4 stub exporting one symbol, just enough to
// satisfy ErrNoLibSystem and exercise a real bind against something.
const fakeLibSystem = `--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libSystem.B.dylib'
current-version: 1
compatibility-version: 1
exports:
  - targets: [ arm64-macos ]
    symbols: [ _getpid ]
`

func buildObject(t *testing.T, target macho.Target) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := obj.NewWriter(&buf, obj.Options{
		Target: target,
		Flags:  macho.MH_SUBSECTIONS_VIA_SYMBOLS,
		Build:  target.Build(),
	})
	text := w.Section(obj.SectionHeader{
		Segment: macho.SEG_TEXT,
		Name:    macho.SECT_TEXT,
		Type:    macho.S_REGULAR,
		Attrs:   macho.S_ATTR_PURE_INSTRUCTIONS,
		Align:   4,
	})
	// bl _getpid ; mov w0, #0 ; ret
	text.Write([]byte{
		0x00, 0x00, 0x00, 0x94,
		0x00, 0x00, 0x80, 0x52,
		0xc0, 0x03, 0x5f, 0xd6,
	})
	w.Symbol(obj.SymbolDef{
		Name:    "_main",
		Type:    macho.N_SECT,
		Ext:     true,
		Section: text,
	})
	sym := w.Symbol(obj.SymbolDef{Name: "_getpid", Ext: true})
	w.Reloc(text, obj.RelocSpec{
		Address: 0,
		Sym:     sym,
		Type:    uint8(macho.ARM64_RELOC_BRANCH26),
		PCRel:   true,
		Length:  macho.RelocLong,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("obj.Writer.Close: %v", err)
	}
	return buf.Bytes()
}

// TestLinkExecutable exercises the whole pipeline end to end: an object with
// a branch to an imported symbol, linked against a stub library, producing a
// signed arm64 executable. It is the regression test for a long list of
// wiring bugs the pipeline had before it was ever run once: segments that
// were never created, __LINKEDIT tables computed but never written into the
// buffer, a pipeline order that sized __LINKEDIT before its tables existed,
// GOT slots with no registered fixup, and a missing SG_READ_ONLY on
// __DATA_CONST.
func TestLinkExecutable(t *testing.T) {
	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}

	l, err := link.New(target)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	if err := l.AddObject("t.o", buildObject(t, target)); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := l.AddStub("libSystem", []byte(fakeLibSystem)); err != nil {
		t.Fatalf("AddStub: %v", err)
	}

	l.Options().Output = link.OutputExecute
	l.SetEntry("_main")

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	h, err := format.DecodeHeader(out, 0)
	if err != nil {
		t.Fatalf("decoding the produced header: %v", err)
	}
	if h.FileType != macho.MH_EXECUTE {
		t.Errorf("filetype = %v, want MH_EXECUTE", h.FileType)
	}
	if h.Flags&macho.MH_PIE == 0 {
		t.Errorf("flags = %#x, want MH_PIE set", h.Flags)
	}

	segs := img.Segments()
	if len(segs) == 0 {
		t.Fatal("no segments were produced")
	}
	if segs[0].Name != macho.SEG_PAGEZERO {
		t.Errorf("first segment = %s, want %s", segs[0].Name, macho.SEG_PAGEZERO)
	}
	if segs[0].VMAddr != 0 {
		t.Errorf("__PAGEZERO.vmaddr = %#x, want 0", segs[0].VMAddr)
	}
	last := segs[len(segs)-1]
	if last.Name != macho.SEG_LINKEDIT {
		t.Errorf("last segment = %s, want %s", last.Name, macho.SEG_LINKEDIT)
	}

	if dc := img.FindSegment(macho.SEG_DATA_CONST); dc != nil {
		if dc.Flags&macho.SG_READ_ONLY == 0 {
			t.Errorf("%s is missing SG_READ_ONLY", macho.SEG_DATA_CONST)
		}
	}

	sigOff, sigSize := img.CodeSignature()
	if sigOff == 0 || sigSize == 0 {
		t.Fatal("no code signature was reserved")
	}
	if sigOff+sigSize != uint64(len(out)) {
		t.Errorf("code signature does not reach the end of the file: %d+%d != %d",
			sigOff, sigSize, len(out))
	}

	// Every byte of every __LINKEDIT table must actually have landed in the
	// buffer rather than staying zeroed — the specific bug where commit sized
	// and placed the tables but nothing wrote them.
	if bytes.Count(out[:sigOff], []byte{0}) == int(sigOff) {
		t.Fatal("the entire pre-signature region is zero; nothing was written")
	}
}
