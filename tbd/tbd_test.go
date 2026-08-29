package tbd_test

import (
	"errors"
	"os"
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/tbd"
)

func arm64macOS(t *testing.T) macho.Target {
	t.Helper()
	tgt, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tgt
}

func hasSymbol(syms []tbd.Symbol, name string) bool {
	for _, s := range syms {
		if s.Name == name {
			return true
		}
	}
	return false
}

const v1 = `---
archs: [ arm64, armv7 ]
platform: ios
install-name: /usr/lib/libFoo.dylib
exports:
  - archs: [ arm64 ]
    symbols: [ _foo, _bar ]
`

func TestParseV1(t *testing.T) {
	s, err := tbd.Parse([]byte(v1))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if s.Version != 1 {
		t.Errorf("Version = %d, want 1", s.Version)
	}
	if s.InstallName != "/usr/lib/libFoo.dylib" {
		t.Errorf("InstallName = %q", s.InstallName)
	}
	// current-version/compatibility-version default to 1.0 when absent.
	if s.CurrentVersion.String() != "1.0.0" && s.CurrentVersion.String() != "1.0" {
		t.Errorf("CurrentVersion = %v, want 1.0", s.CurrentVersion)
	}

	target, err := macho.ParseTarget("arm64-apple-ios17.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if !s.Supports(target) {
		t.Errorf("Supports(%v) = false, want true", target)
	}
	exports := s.Exports(target)
	if !hasSymbol(exports, "_foo") || !hasSymbol(exports, "_bar") {
		t.Errorf("Exports = %v, want _foo and _bar", exports)
	}

	// armv7 is not a target this tree understands, but the arm64 export
	// section limits its own symbols to arm64 regardless.
	x86, _ := macho.ParseTarget("x86_64-apple-ios17.0")
	if s.Supports(x86) {
		t.Errorf("Supports(x86_64) = true for an arm64/armv7-only stub")
	}
}

const v2 = `--- !tapi-tbd-v2
archs: [ arm64 ]
platform: macosx
install-name: /usr/lib/libFoo.dylib
current-version: 1.2.3
compatibility-version: 1.0
exports:
  - archs: [ arm64 ]
    symbols: [ _foo ]
    weak-def-symbols: [ _weakfoo ]
`

func TestParseV2(t *testing.T) {
	s, err := tbd.Parse([]byte(v2))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if s.Version != 2 {
		t.Errorf("Version = %d, want 2", s.Version)
	}
	target := arm64macOS(t)
	exports := s.Exports(target)
	if !hasSymbol(exports, "_foo") {
		t.Errorf("Exports missing _foo: %v", exports)
	}
	var weak tbd.Symbol
	found := false
	for _, e := range exports {
		if e.Name == "_weakfoo" {
			weak, found = e, true
		}
	}
	if !found {
		t.Fatalf("Exports missing _weakfoo: %v", exports)
	}
	if weak.Kind != tbd.Weak {
		t.Errorf("_weakfoo Kind = %v, want Weak", weak.Kind)
	}
}

const v4 = `--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos, x86_64-macos ]
install-name: '/usr/lib/libFoo.dylib'
current-version: 2
exports:
  - targets: [ arm64-macos, x86_64-macos ]
    symbols: [ _foo ]
    weak-symbols: [ _weakfoo ]
    thread-local-symbols: [ _tlv ]
reexported-libraries:
  - targets: [ arm64-macos, x86_64-macos ]
    libraries: [ '/usr/lib/libBar.dylib' ]
`

const v4Bar = `--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos, x86_64-macos ]
install-name: '/usr/lib/libBar.dylib'
current-version: 1
exports:
  - targets: [ arm64-macos, x86_64-macos ]
    symbols: [ _bar_symbol ]
`

func TestParseV4(t *testing.T) {
	s, err := tbd.Parse([]byte(v4))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if s.Version != 4 {
		t.Errorf("Version = %d, want 4", s.Version)
	}
	target := arm64macOS(t)
	exports := s.Exports(target)
	if !hasSymbol(exports, "_foo") {
		t.Errorf("Exports missing _foo: %v", exports)
	}

	var tlv tbd.Symbol
	found := false
	for _, e := range exports {
		if e.Name == "_tlv" {
			tlv, found = e, true
		}
	}
	if !found || tlv.Kind != tbd.ThreadLocal {
		t.Errorf("_tlv not found as ThreadLocal: found=%v kind=%v", found, tlv.Kind)
	}

	libs := s.ReexportedLibraries(target)
	if len(libs) != 1 || libs[0] != "/usr/lib/libBar.dylib" {
		t.Errorf("ReexportedLibraries = %v, want [/usr/lib/libBar.dylib]", libs)
	}

	// x86_64 should see the same exports; a target this section does not
	// list at all should see none.
	x86, _ := macho.ParseTarget("x86_64-apple-macos14.0")
	if !hasSymbol(s.Exports(x86), "_foo") {
		t.Errorf("x86_64 export missing _foo")
	}
}

// TestMultiDocumentInlining checks that Parse's first document carries the
// remaining ones in Inlined, and that Stub.Find follows an install name to
// the right one — the mechanism umbrella libraries like libSystem.tbd use to
// bundle every library they re-export in one file.
func TestMultiDocumentInlining(t *testing.T) {
	combined := v4 + "...\n" + v4Bar
	stubs, err := tbd.ParseAll([]byte(combined))
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}
	if len(stubs) != 2 {
		t.Fatalf("ParseAll returned %d documents, want 2", len(stubs))
	}

	top, err := tbd.Parse([]byte(combined))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(top.Inlined) != 1 {
		t.Fatalf("Inlined has %d documents, want 1", len(top.Inlined))
	}
	if top.Inlined[0].InstallName != "/usr/lib/libBar.dylib" {
		t.Errorf("Inlined[0].InstallName = %q", top.Inlined[0].InstallName)
	}

	found := top.Find("/usr/lib/libBar.dylib")
	if found == nil {
		t.Fatal("Find did not locate the inlined libBar document")
	}
	target := arm64macOS(t)
	if !hasSymbol(found.Exports(target), "_bar_symbol") {
		t.Errorf("found stub's exports = %v, want _bar_symbol", found.Exports(target))
	}

	if top.Find("/usr/lib/libFoo.dylib") != top {
		t.Error("Find on the top-level install name should return the receiver itself")
	}
	if top.Find("/usr/lib/nonexistent.dylib") != nil {
		t.Error("Find on an unknown install name should return nil")
	}
}

func TestParseRejectsV5JSON(t *testing.T) {
	_, err := tbd.Parse([]byte(`{"tapi_tbd_version": 5}`))
	if !errors.Is(err, tbd.ErrUnsupportedTBDVersion) {
		t.Errorf("Parse(v5 json) error = %v, want ErrUnsupportedTBDVersion", err)
	}
}

func TestParseRejectsMissingInstallName(t *testing.T) {
	_, err := tbd.Parse([]byte("---\narchs: [ arm64 ]\nplatform: macosx\n"))
	if !errors.Is(err, tbd.ErrMalformed) {
		t.Errorf("Parse with no install-name error = %v, want ErrMalformed", err)
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	_, err := tbd.Parse(nil)
	if err == nil {
		t.Fatal("Parse(nil) succeeded, want an error")
	}
}

// TestReadRealSystemLibSystem is an integration check against the real
// libSystem.tbd shipped with the toolchain: parse it, follow its re-exported
// libraries, and confirm a symbol that lives only in a re-exported library
// (not in libSystem's own direct exports) resolves via Find.
func TestReadRealSystemLibSystem(t *testing.T) {
	candidates := []string{
		"/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib/libSystem.tbd",
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no known libSystem.tbd found on this machine")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s, err := tbd.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	target := arm64macOS(t)
	if !s.Supports(target) {
		t.Fatalf("libSystem.tbd does not support %v: archs %v", target, s.ArchNames())
	}

	libs := s.ReexportedLibraries(target)
	if len(libs) == 0 {
		t.Fatal("libSystem.tbd re-exports nothing; expected libsystem_kernel etc.")
	}

	// _getpid is a kernel syscall, not one of libSystem's own direct exports —
	// it must be reached by following a re-exported library.
	if hasSymbol(s.Exports(target), "_getpid") {
		t.Skip("_getpid is now a direct export; re-export following can't be exercised this way")
	}
	var kernel *tbd.Stub
	for _, name := range libs {
		if sub := s.Find(name); sub != nil && hasSymbol(sub.Exports(target), "_getpid") {
			kernel = sub
			break
		}
	}
	if kernel == nil {
		t.Error("could not find _getpid in any re-exported library reachable via Find")
	}
}
