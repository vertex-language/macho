package fat_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/fat"
	"github.com/vertex-language/macho/internal/binio"
)

func TestRoundTrip(t *testing.T) {
	members := []fat.Member{
		{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, Data: bytes.Repeat([]byte{0xAA}, 100)},
		{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64E, Data: bytes.Repeat([]byte{0xBB}, 200)},
		{CPU: macho.CPU_TYPE_X86_64, SubCPU: macho.CPU_SUBTYPE_X86_64_ALL, Data: bytes.Repeat([]byte{0xCC}, 300)},
	}
	data, err := fat.Bytes(members)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !macho.IsFat(data) {
		t.Fatal("written file is not recognized as fat")
	}

	f, err := fat.NewFile(binio.ExtentOf(data))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if len(f.Arches) != len(members) {
		t.Fatalf("got %d slices, want %d", len(f.Arches), len(members))
	}

	names := f.Names()
	wantNames := map[string]bool{"arm64": false, "arm64e": false, "x86_64": false}
	for _, n := range names {
		if _, ok := wantNames[n]; !ok {
			t.Errorf("unexpected slice name %q", n)
		}
		wantNames[n] = true
	}
	for n, seen := range wantNames {
		if !seen {
			t.Errorf("missing slice %q", n)
		}
	}

	for _, m := range members {
		a, err := f.Exact(m.CPU, m.SubCPU)
		if err != nil {
			t.Fatalf("Exact(%s): %v", macho.ArchName(m.CPU, m.SubCPU), err)
		}
		got, err := a.Bytes()
		if err != nil {
			t.Fatalf("Bytes for %s: %v", a.Name(), err)
		}
		if !bytes.Equal(got, m.Data) {
			t.Errorf("%s contents do not match: got %d bytes, want %d", a.Name(), len(got), len(m.Data))
		}
	}
}

// TestGradedSelection checks the fallback rules Find documents: an exact
// subtype always wins, a generic slice may serve a specific request, and the
// reverse never happens.
func TestGradedSelection(t *testing.T) {
	// Only a generic arm64 slice: an arm64e request must fall back to it.
	generic := []fat.Member{
		{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, Data: bytes.Repeat([]byte{1}, 64)},
	}
	data, err := fat.Bytes(generic)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	f, err := fat.NewFile(binio.ExtentOf(data))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if _, err := f.Find(macho.CPU_TYPE_ARM64, macho.CPU_SUBTYPE_ARM64E); err != nil {
		t.Errorf("arm64e request against a generic-only file should fall back: %v", err)
	}
	// But Exact must refuse the same fallback.
	if _, err := f.Exact(macho.CPU_TYPE_ARM64, macho.CPU_SUBTYPE_ARM64E); err == nil {
		t.Error("Exact(arm64e) unexpectedly succeeded against a generic-only file")
	}

	// Only an arm64e slice: a plain arm64 request must NOT be served it — the
	// fallback direction the package doc explicitly says never happens.
	e := []fat.Member{
		{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64E, Data: bytes.Repeat([]byte{2}, 64)},
	}
	data2, err := fat.Bytes(e)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	f2, err := fat.NewFile(binio.ExtentOf(data2))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if _, err := f2.Find(macho.CPU_TYPE_ARM64, macho.CPU_SUBTYPE_ARM64_ALL); err == nil {
		t.Error("a plain arm64 request was served an arm64e-only slice; that direction must not fall back")
	}

	// A mixed file: an exact match wins over a generic one that could also
	// serve the request.
	mixed := []fat.Member{
		{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, Data: bytes.Repeat([]byte{3}, 64)},
		{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64E, Data: bytes.Repeat([]byte{4}, 64)},
	}
	data3, err := fat.Bytes(mixed)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	f3, err := fat.NewFile(binio.ExtentOf(data3))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	a, err := f3.Find(macho.CPU_TYPE_ARM64, macho.CPU_SUBTYPE_ARM64E)
	if err != nil {
		t.Fatalf("Find(arm64e): %v", err)
	}
	if a.SubCPU.Base() != macho.CPU_SUBTYPE_ARM64E {
		t.Errorf("Find(arm64e) on a mixed file returned %s, want the exact arm64e slice", a.Name())
	}
}

func TestDuplicateArchRejected(t *testing.T) {
	members := []fat.Member{
		{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, Data: []byte{1, 2, 3, 4}},
		{CPU: macho.CPU_TYPE_ARM64, SubCPU: macho.CPU_SUBTYPE_ARM64_ALL, Data: []byte{5, 6, 7, 8}},
	}
	if _, err := fat.Bytes(members); err == nil {
		t.Fatal("Bytes accepted two slices with the same architecture")
	}
}

func TestNoSlicesRejected(t *testing.T) {
	if _, err := fat.Bytes(nil); err == nil {
		t.Fatal("Bytes accepted an empty member list")
	}
}

func TestNewFileRejectsThin(t *testing.T) {
	// A thin macho.Is-recognized header, not a fat one: NewFile must say so
	// distinctly (ErrThinFile) rather than a generic parse failure.
	thin := []byte{0xcf, 0xfa, 0xed, 0xfe} // MH_MAGIC_64, little-endian
	thin = append(thin, make([]byte, 32)...)
	if _, err := fat.NewFile(binio.ExtentOf(thin)); err == nil {
		t.Fatal("NewFile accepted a thin Mach-O header")
	}
}

func TestNewFileRejectsGarbage(t *testing.T) {
	if _, err := fat.NewFile(binio.ExtentOf([]byte("not a mach-o file at all"))); err == nil {
		t.Fatal("NewFile accepted arbitrary garbage")
	}
}

// TestReadRealUniversalArchive is an integration check against a real,
// universal static library shipped with the toolchain, if present. Skipped
// rather than failed when the exact SDK layout differs across machines.
func TestReadRealUniversalArchive(t *testing.T) {
	candidates := []string{
		"/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib/libl.a",
	}
	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no known universal static archive found on this machine")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	f, err := fat.NewFile(binio.ExtentOf(data))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if len(f.Arches) < 2 {
		t.Fatalf("expected a multi-architecture archive, got %d slice(s)", len(f.Arches))
	}
	for _, a := range f.Arches {
		ext, err := a.Extent()
		if err != nil {
			t.Fatalf("Extent for %s: %v", a.Name(), err)
		}
		if ext.Size() != int64(a.Size) {
			t.Errorf("%s extent size = %d, want %d", a.Name(), ext.Size(), a.Size)
		}
	}
}
