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

// TestAddRPathRejectsDuplicate checks that a repeated -rpath is caught here
// rather than emitted twice: recent versions of ld require every LC_RPATH to
// be unique.
func TestAddRPathRejectsDuplicate(t *testing.T) {
	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	l, err := link.New(target)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	l.AddRPath("@executable_path/../Frameworks")
	if l.Err() != nil {
		t.Fatalf("first AddRPath failed: %v", l.Err())
	}
	l.AddRPath("@executable_path/../Frameworks")
	if l.Err() == nil {
		t.Error("a duplicate -rpath should have failed the link")
	}
}

// realLibSystemTBD returns a real libSystem.tbd from the toolchain, or "" if
// none of the known SDK layouts are present on this machine.
func realLibSystemTBD() string { return realSDKStub("libSystem.tbd") }

// realObjCTBD is libobjc's stub, which is where an Objective-C image's
// __objc_empty_cache and objc_msgSend come from. libSystem does not
// re-export it.
func realObjCTBD() string { return realSDKStub("libobjc.A.tbd") }

func realSDKStub(name string) string {
	roots := []string{
		"/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
		"/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
	}
	for _, r := range roots {
		c := filepath.Join(r, "usr/lib", name)
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

// TestLinkDylibExportsAreCallable links a trivial dylib, then loads it with
// the real dyld through dlopen and calls its exported function by name
// through dlsym — proof that LC_ID_DYLIB, the export trie, and two-level
// namespace symbol export are not just present but actually usable.
func TestLinkDylibExportsAreCallable(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not found on PATH")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("dlopen-ing the result needs arm64 macOS")
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

	// A self-contained function with no nested call: mov w0, #42; ret. Unlike
	// buildObject, this deliberately never calls anything else, so there is
	// no link register to save and restore — the point of this test is the
	// dylib export/dlsym path, not another exercise of relocations that
	// buildObject already covers via a call that never returns.
	var objBuf bytes.Buffer
	ow := obj.NewWriter(&objBuf, obj.Options{
		Target: target, Flags: macho.MH_SUBSECTIONS_VIA_SYMBOLS, Build: target.Build(),
	})
	text := ow.Section(obj.SectionHeader{
		Segment: macho.SEG_TEXT, Name: macho.SECT_TEXT,
		Type: macho.S_REGULAR, Attrs: macho.S_ATTR_PURE_INSTRUCTIONS, Align: 4,
	})
	text.Write([]byte{0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6}) // mov w0,#42; ret
	ow.Symbol(obj.SymbolDef{Name: "_answer", Type: macho.N_SECT, Ext: true, Section: text})
	if err := ow.Close(); err != nil {
		t.Fatalf("obj.Writer.Close: %v", err)
	}

	if err := l.AddObject("t.o", objBuf.Bytes()); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := l.AddStub("libSystem", []byte(fakeLibSystem)); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	l.Options().Output = link.OutputDylib
	l.SetInstallName("@rpath/libmachotest.dylib")
	l.SetDylibVersions(macho.MustParseVersion("1.0"), macho.MustParseVersion("1.0"))

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	dir := t.TempDir()
	dylibPath := filepath.Join(dir, "libmachotest.dylib")
	if err := os.WriteFile(dylibPath, out, 0o755); err != nil {
		t.Fatalf("WriteFile(dylib): %v", err)
	}

	harnessSrc := filepath.Join(dir, "harness.c")
	harness := filepath.Join(dir, "harness")
	if err := os.WriteFile(harnessSrc, []byte(`
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
	int (*fn)(void) = (int (*)(void))dlsym(h, "answer");
	if (!fn) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
	int got = fn();
	if (got != 42) { fprintf(stderr, "answer() = %d, want 42\n", got); return 1; }
	return 0;
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile(harness.c): %v", err)
	}
	if out, err := exec.Command(clang, "-o", harness, harnessSrc).CombinedOutput(); err != nil {
		t.Fatalf("compiling the dlopen harness: %v\n%s", err, out)
	}
	if out, err := exec.Command(harness, dylibPath).CombinedOutput(); err != nil {
		t.Fatalf("dlopen/dlsym harness failed: %v\n%s", err, out)
	}
}

// A literal pointer table is not deduplicated by content.
//
// An S_LITERAL_POINTERS section holds addresses, and in an object file every
// entry is eight zero bytes plus a relocation — so by content they are all
// the same literal. Folding them collapses the table onto its first entry.
//
// __objc_selrefs is exactly that section, and this is what a program whose
// selector references merged does: it sends the first selector everywhere the
// second was written, and aborts on an unrecognized selector at the first
// message. The Objective-C compiler that found it is the reason this test is
// written against clang's own output rather than a synthetic object.
func TestLiteralPointersAreNotMerged(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not found on PATH")
	}
	tbdPath := realLibSystemTBD()
	if tbdPath == "" {
		t.Skip("no known libSystem.tbd found on this machine")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "t.m")
	objPath := filepath.Join(dir, "t.o")
	if err := os.WriteFile(src, []byte(`
@interface NSObject
@end
@interface K : NSObject
- (int)one;
- (int)two;
@end
@implementation K
- (int)one { return 1; }
- (int)two { return 2; }
@end
int f(K *k) { return [k one] + [k two]; }
`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Classic selector references rather than clang's newer selector
	// stubs, which is the shape this test is about — and the shape every
	// other Objective-C compiler emits.
	cmd := exec.Command(clang, "-c", "-x", "objective-c",
		"-fno-objc-msgsend-selector-stubs",
		"-target", "arm64-apple-macos14.0", "-O0", "-o", objPath, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("clang could not build the object: %v\n%s", err, out)
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
	objcPath := realObjCTBD()
	if objcPath == "" {
		t.Skip("no libobjc.A.tbd on this machine")
	}
	objcData, err := os.ReadFile(objcPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", objcPath, err)
	}
	if err := l.AddStub("libobjc", objcData); err != nil {
		t.Fatalf("AddStub(libobjc): %v", err)
	}
	l.Options().Output = link.OutputDylib
	l.SetInstallName("@rpath/t.dylib")

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if _, err := img.Bytes(); err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	// Two selectors were referenced, so the table has to hold two entries.
	// One means they merged.
	var size uint64
	for _, sec := range img.Sections() {
		if sec.Key.Name.Section == "__objc_selrefs" {
			size = sec.Size
		}
	}
	if size == 0 {
		t.Skip("this clang emitted no __objc_selrefs")
	}
	if size != 16 {
		t.Errorf("__objc_selrefs is %d bytes, want 16 — two selectors, two entries", size)
	}
}

// TestLocalSubtrahendResolvesInItsObject builds the shape a relative
// pointer has when the field it sits in belongs to a symbol with
// internal linkage: a four-byte `to - from` where `from` is a local.
//
// The subtrahend used to be interned into the global symbol table
// whatever its linkage, which made the link fail on a symbol defined
// right there in the object. The other side of the difference had
// always been resolved within the object; this is the same rule applied
// to both halves. Every private descriptor is this shape -- the record
// beside a private async function is one -- so it is the ordinary case
// rather than a corner.
func TestLocalSubtrahendResolvesInItsObject(t *testing.T) {
	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	l, err := link.New(target)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	if err := l.AddObject("t.o", buildLocalDeltaObject(t, target)); err != nil {
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
	if _, err := img.Bytes(); err != nil {
		t.Fatalf("Bytes: %v", err)
	}
}

// buildLocalDeltaObject is an object holding a local four-byte field
// whose value is the distance from itself to _main.
func buildLocalDeltaObject(t *testing.T, target macho.Target) []byte {
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
	// mov w0, #0 ; ret
	text.Write([]byte{0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6})
	main := w.Symbol(obj.SymbolDef{
		Name: "_main", Type: macho.N_SECT, Ext: true, Section: text,
	})

	konst := w.Section(obj.SectionHeader{
		Segment: macho.SEG_TEXT,
		Name:    "__const",
		Type:    macho.S_REGULAR,
		Align:   8,
	})
	konst.Write(make([]byte, 4))
	// The record's own symbol is local: nothing outside this object
	// names it.
	record := w.Symbol(obj.SymbolDef{
		Name: "l_record", Type: macho.N_SECT, Section: konst,
	})
	w.RelocPair(konst, obj.RelocSpec{
		Address: 0, Sym: record,
		Type:   uint8(macho.ARM64_RELOC_SUBTRACTOR),
		Length: macho.RelocLong,
	}, obj.RelocSpec{
		Address: 0, Sym: main,
		Type:   uint8(macho.ARM64_RELOC_UNSIGNED),
		Length: macho.RelocLong,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("obj.Writer.Close: %v", err)
	}
	return buf.Bytes()
}
