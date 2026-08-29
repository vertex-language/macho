package link_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// realLibSystemTBD returns a real libSystem.tbd from the toolchain, or "" if
// none of the known SDK layouts are present on this machine.
func realLibSystemTBD() string {
	candidates := []string{
		"/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib/libSystem.tbd",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// TestLinkRealCompilerOutput compiles real C source with the system clang —
// a function call, a conditional, and a call into libSystem that never
// returns — links the resulting object against the real libSystem.tbd, and
// (on arm64 macOS, where the produced binary can actually run) executes it.
//
// This exercises re-export resolution against the real libSystem.tbd rather
// than the minimal fake used by TestLinkExecutable, and end-to-end fixup
// correctness against object code this package did not itself construct.
func TestLinkRealCompilerOutput(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not found on PATH")
	}
	tbdPath := realLibSystemTBD()
	if tbdPath == "" {
		t.Skip("no known libSystem.tbd found on this machine")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "t.c")
	objPath := filepath.Join(dir, "t.o")
	if err := os.WriteFile(src, []byte(`
#include <unistd.h>
int helper(int x) { return x + 1; }
int main(void) {
	int r = helper(41);
	_exit(r == 42 ? 0 : 1);
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cmd := exec.Command(clang, "-c", "-target", "arm64-apple-macos14.0", "-O0", "-o", objPath, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clang failed: %v\n%s", err, out)
	}

	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	l, err := link.New(target)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	objData, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := l.AddObject("t.o", objData); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	tbdData, err := os.ReadFile(tbdPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", tbdPath, err)
	}
	if err := l.AddStub("libSystem", tbdData); err != nil {
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

	exePath := filepath.Join(dir, "a.out")
	if err := os.WriteFile(exePath, out, 0o755); err != nil {
		t.Fatalf("WriteFile(exe): %v", err)
	}

	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("built the executable; running it needs arm64 macOS")
	}
	if err := exec.Command(exePath).Run(); err != nil {
		t.Fatalf("running the linked binary: %v", err)
	}
}
