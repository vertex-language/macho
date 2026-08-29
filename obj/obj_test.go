package obj_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/obj"
)

func target(t *testing.T) macho.Target {
	t.Helper()
	tgt, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	return tgt
}

// TestWriteReadRoundTrip builds an object with two symbols, one relocation, a
// zerofill (__bss) section, and a common symbol, then reads it back and
// checks everything that went in comes back out unchanged.
func TestWriteReadRoundTrip(t *testing.T) {
	tgt := target(t)
	var buf bytes.Buffer
	w := obj.NewWriter(&buf, obj.Options{
		Target: tgt,
		Flags:  macho.MH_SUBSECTIONS_VIA_SYMBOLS,
		Build:  tgt.Build(),
	})

	text := w.Section(obj.SectionHeader{
		Segment: macho.SEG_TEXT, Name: macho.SECT_TEXT,
		Type: macho.S_REGULAR, Attrs: macho.S_ATTR_PURE_INSTRUCTIONS, Align: 4,
	})
	code := []byte{
		0x00, 0x00, 0x00, 0x94, // bl (patched)
		0xc0, 0x03, 0x5f, 0xd6, // ret
	}
	text.Write(code)

	bss := w.Section(obj.SectionHeader{
		Segment: macho.SEG_DATA, Name: macho.SECT_BSS,
		Type: macho.S_ZEROFILL, Align: 8,
	})
	bss.Grow(16)

	w.Symbol(obj.SymbolDef{Name: "_main", Type: macho.N_SECT, Ext: true, Section: text})
	w.Symbol(obj.SymbolDef{Name: "_local_data", Type: macho.N_SECT, Section: bss, Value: 8})
	ext := w.Symbol(obj.SymbolDef{Name: "_extern_fn", Ext: true})
	// A common symbol: external, undefined, with a nonzero value (its size).
	w.Symbol(obj.SymbolDef{Name: "_a_common", Ext: true, Value: 32, CommonAlign: 4})

	w.Reloc(text, obj.RelocSpec{
		Address: 0, Sym: ext, Type: uint8(macho.ARM64_RELOC_BRANCH26),
		PCRel: true, Length: macho.RelocLong,
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := obj.NewFile(binio.ExtentOf(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	defer f.Close()

	if f.CPU() != tgt.CPU || f.SubCPU().Base() != tgt.SubCPU.Base() {
		t.Errorf("arch = %s, want %s", f.Arch(), macho.ArchName(tgt.CPU, tgt.SubCPU))
	}
	if !f.Subsections() {
		t.Error("Subsections() = false, want true (MH_SUBSECTIONS_VIA_SYMBOLS was set)")
	}
	if got, want := f.FileType(), macho.MH_OBJECT; got != want {
		t.Errorf("FileType = %v, want %v", got, want)
	}

	bi, ok := f.Build()
	if !ok {
		t.Error("Build() ok = false, want true")
	} else if bi.Platform != tgt.Platform {
		t.Errorf("Build().Platform = %v, want %v", bi.Platform, tgt.Platform)
	}

	textSec := f.Section(macho.Sec(macho.SEG_TEXT, macho.SECT_TEXT))
	if textSec == nil {
		t.Fatal("__TEXT,__text section not found")
	}
	data, err := textSec.Data()
	if err != nil {
		t.Fatalf("text Data: %v", err)
	}
	if !bytes.Equal(data, code) {
		t.Errorf("text contents = %x, want %x", data, code)
	}

	bssSec := f.Section(macho.Sec(macho.SEG_DATA, macho.SECT_BSS))
	if bssSec == nil {
		t.Fatal("__DATA,__bss section not found")
	}
	if !bssSec.Zerofill() {
		t.Error("__bss section is not marked zerofill")
	}
	if bssSec.Size != 16 {
		t.Errorf("__bss size = %d, want 16", bssSec.Size)
	}

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	byName := make(map[string]*obj.Symbol, len(syms))
	for _, s := range syms {
		byName[s.Name] = s
	}

	main, ok := byName["_main"]
	if !ok {
		t.Fatal("_main not found")
	}
	if !main.Ext() || !main.Defined() {
		t.Errorf("_main: Ext=%v Defined=%v, want true,true", main.Ext(), main.Defined())
	}

	local, ok := byName["_local_data"]
	if !ok {
		t.Fatal("_local_data not found")
	}
	if local.Ext() {
		t.Error("_local_data should not be external")
	}
	// Value was submitted as an 8-byte offset within bss; Close adds the
	// section's own assigned address for an N_SECT symbol, per SymbolDef.
	if want := bssSec.Addr + 8; local.Value != want {
		t.Errorf("_local_data.Value = %d, want %d (bss addr %d + offset 8)", local.Value, want, bssSec.Addr)
	}

	fn, ok := byName["_extern_fn"]
	if !ok {
		t.Fatal("_extern_fn not found")
	}
	if !fn.Undefined() {
		t.Error("_extern_fn should be undefined")
	}

	common, ok := byName["_a_common"]
	if !ok {
		t.Fatal("_a_common not found")
	}
	if !common.Common() {
		t.Error("_a_common should report Common() = true")
	}
	if common.Value != 32 {
		t.Errorf("_a_common.Value (size) = %d, want 32", common.Value)
	}
	if common.CommonAlign() != 4 {
		t.Errorf("_a_common.CommonAlign() = %d, want 4", common.CommonAlign())
	}

	relocs, err := textSec.Relocs()
	if err != nil {
		t.Fatalf("Relocs: %v", err)
	}
	if len(relocs) != 1 {
		t.Fatalf("got %d relocations, want 1", len(relocs))
	}
	r := relocs[0]
	if r.Address != 0 {
		t.Errorf("reloc.Address = %d, want 0", r.Address)
	}
	if !r.Extern {
		t.Error("reloc.Extern = false, want true")
	}
	if !r.PCRel {
		t.Error("reloc.PCRel = false, want true")
	}
	if macho.ARM64Reloc(r.Type) != macho.ARM64_RELOC_BRANCH26 {
		t.Errorf("reloc.Type = %v, want ARM64_RELOC_BRANCH26", r.Type)
	}
}

// TestAtomsUnderSubsections checks that MH_SUBSECTIONS_VIA_SYMBOLS splitting
// produces one atom per defining symbol, in address order.
func TestAtomsUnderSubsections(t *testing.T) {
	tgt := target(t)
	var buf bytes.Buffer
	w := obj.NewWriter(&buf, obj.Options{
		Target: tgt, Flags: macho.MH_SUBSECTIONS_VIA_SYMBOLS, Build: tgt.Build(),
	})
	text := w.Section(obj.SectionHeader{
		Segment: macho.SEG_TEXT, Name: macho.SECT_TEXT,
		Type: macho.S_REGULAR, Attrs: macho.S_ATTR_PURE_INSTRUCTIONS, Align: 4,
	})
	nop := []byte{0x1f, 0x20, 0x03, 0xd5}
	ret := []byte{0xc0, 0x03, 0x5f, 0xd6}
	text.Write(nop) // _first at offset 0
	text.Write(ret) // _second at offset 4
	w.Symbol(obj.SymbolDef{Name: "_first", Type: macho.N_SECT, Ext: true, Section: text, Value: 0})
	w.Symbol(obj.SymbolDef{Name: "_second", Type: macho.N_SECT, Ext: true, Section: text, Value: 4})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := obj.NewFile(binio.ExtentOf(buf.Bytes()))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	defer f.Close()

	sec := f.Section(macho.Sec(macho.SEG_TEXT, macho.SECT_TEXT))
	atoms, err := sec.Atoms()
	if err != nil {
		t.Fatalf("Atoms: %v", err)
	}
	if len(atoms) != 2 {
		t.Fatalf("got %d atoms, want 2", len(atoms))
	}
	if atoms[0].Name() != "_first" || atoms[1].Name() != "_second" {
		t.Errorf("atom names = %q, %q, want _first, _second", atoms[0].Name(), atoms[1].Name())
	}
	if got, err := atoms[0].Data(); err != nil || !bytes.Equal(got, nop) {
		t.Errorf("_first data = %x, %v, want %x", got, err, nop)
	}
	if got, err := atoms[1].Data(); err != nil || !bytes.Equal(got, ret) {
		t.Errorf("_second data = %x, %v, want %x", got, err, ret)
	}
}

func TestNewFileRejectsNonObject(t *testing.T) {
	if _, err := obj.NewFile(binio.ExtentOf([]byte("not a mach-o object"))); err == nil {
		t.Fatal("NewFile accepted garbage")
	}
}

// TestReadRealCompilerOutput is an integration check: compile a small C file
// with the system clang and read the resulting object with this package,
// skipped if clang is not available.
func TestReadRealCompilerOutput(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not found on PATH")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "t.c")
	out := filepath.Join(dir, "t.o")
	if err := os.WriteFile(src, []byte(`
int helper(int x) { return x + 1; }
int main(void) { return helper(41); }
`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cmd := exec.Command(clang, "-c", "-target", "arm64-apple-macos14.0", "-O0", "-o", out, src)
	if outp, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clang failed: %v\n%s", err, outp)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	f, err := obj.NewFile(binio.ExtentOf(data))
	if err != nil {
		t.Fatalf("NewFile on clang output: %v", err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	var sawMain, sawHelper bool
	for _, s := range syms {
		switch s.Name {
		case "_main":
			sawMain = s.Ext() && s.Defined()
		case "_helper":
			sawHelper = s.Defined()
		}
	}
	if !sawMain {
		t.Error("_main not found as an external definition in clang's output")
	}
	if !sawHelper {
		t.Error("_helper not found as a definition in clang's output")
	}

	textSec := f.Section(macho.Sec(macho.SEG_TEXT, macho.SECT_TEXT))
	if textSec == nil {
		t.Fatal("clang's output has no __TEXT,__text section")
	}
	if textSec.Size == 0 {
		t.Error("__text section is empty")
	}
}
