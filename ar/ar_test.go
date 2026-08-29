package ar_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/vertex-language/macho/ar"
	"github.com/vertex-language/macho/fat"
	"github.com/vertex-language/macho/internal/binio"
)

func TestIsArchive(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"magic", []byte(ar.Magic + "junk"), true},
		{"exact magic, no more", []byte(ar.Magic), true},
		{"too short", []byte("!<arch"), false},
		{"empty", nil, false},
		{"wrong magic", []byte("!<arch>\x00garbage"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ar.IsArchive(c.data); got != c.want {
				t.Errorf("IsArchive(%q) = %v, want %v", c.data, got, c.want)
			}
		})
	}
}

func writeArchive(t *testing.T, opts ar.Options, inputs []ar.Input) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := ar.NewWriter(&buf, opts)
	for _, in := range inputs {
		w.Add(in)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Writer.Close: %v", err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	inputs := []ar.Input{
		{Name: "foo.o", Data: []byte("foo contents"), Symbols: []string{"_foo", "_foo_helper"}},
		{Name: "bar.o", Data: []byte("bar contents, a bit longer than foo's"), Symbols: []string{"_bar"}},
		{Name: "empty.o", Data: nil, Symbols: nil},
	}
	data := writeArchive(t, ar.Options{Deterministic: true}, inputs)

	if !ar.IsArchive(data) {
		t.Fatal("written archive does not start with the ar magic")
	}

	f, err := ar.NewFile(binio.ExtentOf(data))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if len(f.Members) != len(inputs) {
		t.Fatalf("got %d members, want %d", len(f.Members), len(inputs))
	}
	for i, in := range inputs {
		m := f.Members[i]
		if m.Name != in.Name {
			t.Errorf("member %d name = %q, want %q", i, m.Name, in.Name)
		}
		got, err := m.Bytes()
		if err != nil {
			t.Fatalf("member %d Bytes: %v", i, err)
		}
		// Member.Size includes Darwin's trailing alignment padding, which is
		// documented behavior (see Member.Size) rather than something a
		// reader can strip on its own — a Mach-O caller does not need to,
		// since its own load commands describe the real extent.
		if !bytes.Equal(got[:len(in.Data)], in.Data) {
			t.Errorf("member %d contents = %q, want %q", i, got[:len(in.Data)], in.Data)
		}
		if pad := got[len(in.Data):]; !bytes.Equal(pad, make([]byte, len(pad))) {
			t.Errorf("member %d trailing padding is non-zero: %q", i, pad)
		}
	}

	// Every symbol should resolve to its member through the table of
	// contents.
	for _, in := range inputs {
		for _, sym := range in.Symbols {
			m, err := f.Lookup(sym)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", sym, err)
			}
			if m == nil {
				t.Fatalf("Lookup(%q) = nil, want %s", sym, in.Name)
			}
			if m.Name != in.Name {
				t.Errorf("Lookup(%q) = %s, want %s", sym, m.Name, in.Name)
			}
		}
	}

	// A symbol nothing defines resolves to nothing, without an error: not
	// finding a symbol in one archive is routine, not exceptional.
	m, err := f.Lookup("_nonexistent")
	if err != nil {
		t.Fatalf("Lookup(_nonexistent): %v", err)
	}
	if m != nil {
		t.Errorf("Lookup(_nonexistent) = %s, want nil", m.Name)
	}

	toc, err := f.TOC()
	if err != nil {
		t.Fatalf("TOC: %v", err)
	}
	if !toc.Sorted {
		t.Errorf("TOC.Sorted = false, want true (no duplicate symbols)")
	}
	if len(toc.Entries) != 3 {
		t.Errorf("TOC has %d entries, want 3", len(toc.Entries))
	}
}

// TestDuplicateSymbolFallsBackToUnsorted checks that two members defining the
// same symbol name still produce a readable archive: the table of contents
// cannot be sorted-searchable in that case (a search would only ever find
// one), so the writer falls back to the unsorted form, and both entries must
// still be recoverable by walking it.
func TestDuplicateSymbolFallsBackToUnsorted(t *testing.T) {
	inputs := []ar.Input{
		{Name: "a.o", Data: []byte("aaaa"), Symbols: []string{"_dup", "_only_a"}},
		{Name: "b.o", Data: []byte("bbbb"), Symbols: []string{"_dup", "_only_b"}},
	}
	data := writeArchive(t, ar.Options{Deterministic: true}, inputs)

	f, err := ar.NewFile(binio.ExtentOf(data))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	toc, err := f.TOC()
	if err != nil {
		t.Fatalf("TOC: %v", err)
	}
	if toc.Sorted {
		t.Error("TOC.Sorted = true, want false (duplicate _dup should force the unsorted form)")
	}

	// _dup resolves to whichever member's entry appears first in the
	// (unsorted, offset-ordered) table, which is "a.o" here. The important
	// property is that Lookup does not error and that _only_a/_only_b still
	// resolve correctly around it.
	if m, err := f.Lookup("_only_a"); err != nil || m == nil || m.Name != "a.o" {
		t.Errorf("Lookup(_only_a) = %v, %v, want a.o", m, err)
	}
	if m, err := f.Lookup("_only_b"); err != nil || m == nil || m.Name != "b.o" {
		t.Errorf("Lookup(_only_b) = %v, %v, want b.o", m, err)
	}
	if m, err := f.Lookup("_dup"); err != nil || m == nil {
		t.Errorf("Lookup(_dup) = %v, %v, want a resolvable member", m, err)
	}
}

// TestLongNameUsesExtendedForm exercises the BSD "#1/N" extended-name path
// with a name well past the fixed 16-byte field.
func TestLongNameUsesExtendedForm(t *testing.T) {
	longName := "this_is_a_member_name_much_longer_than_sixteen_bytes.o"
	data := writeArchive(t, ar.Options{Deterministic: true}, []ar.Input{
		{Name: longName, Data: []byte("payload"), Symbols: []string{"_sym"}},
	})

	f, err := ar.NewFile(binio.ExtentOf(data))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if len(f.Members) != 1 {
		t.Fatalf("got %d members, want 1", len(f.Members))
	}
	if f.Members[0].Name != longName {
		t.Errorf("member name = %q, want %q", f.Members[0].Name, longName)
	}
}

// TestNewFileRejectsNonArchive checks the magic is actually enforced.
func TestNewFileRejectsNonArchive(t *testing.T) {
	_, err := ar.NewFile(binio.ExtentOf([]byte("not an archive at all")))
	if err == nil {
		t.Fatal("NewFile accepted data with no ar magic")
	}
}

// TestReadRealSystemArchive is an integration check against a real,
// universal (fat) static archive shipped with the toolchain, if one is
// present on this machine. It is skipped rather than failing when the SDK
// layout differs, since the exact path is host-specific.
func TestReadRealSystemArchive(t *testing.T) {
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
		t.Skip("no known system static archive found on this machine")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	ff, err := fat.NewFile(binio.ExtentOf(data))
	if err != nil {
		t.Fatalf("fat.NewFile: %v", err)
	}
	names := ff.Names()
	if len(names) == 0 {
		t.Fatal("universal archive has no slices")
	}
	for _, name := range names {
		a, err := ff.FindName(name)
		if err != nil {
			t.Fatalf("FindName(%s): %v", name, err)
		}
		ext, err := a.Extent()
		if err != nil {
			t.Fatalf("Extent for %s: %v", name, err)
		}
		f, err := ar.NewFile(ext)
		if err != nil {
			t.Fatalf("ar.NewFile(%s slice): %v", name, err)
		}
		if len(f.Members) == 0 {
			t.Errorf("%s slice has no members", name)
		}
		// The table of contents, if any, must at least be readable without
		// error; a real ranlib archive always has one.
		if _, err := f.TOC(); err != nil {
			t.Errorf("%s slice: TOC: %v", name, err)
		}
	}
}
