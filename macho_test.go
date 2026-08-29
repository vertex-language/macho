package macho_test

import (
	"testing"

	"github.com/vertex-language/macho"
)

func TestParseTargetBasic(t *testing.T) {
	tgt, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if tgt.CPU != macho.CPU_TYPE_ARM64 {
		t.Errorf("CPU = %v, want CPU_TYPE_ARM64", tgt.CPU)
	}
	if tgt.SubCPU.Base() != macho.CPU_SUBTYPE_ARM64_ALL {
		t.Errorf("SubCPU = %v, want CPU_SUBTYPE_ARM64_ALL", tgt.SubCPU)
	}
	if tgt.Platform != macho.PlatformMacOS {
		t.Errorf("Platform = %v, want PlatformMacOS", tgt.Platform)
	}
	if tgt.MinOS != macho.MustParseVersion("14.0") {
		t.Errorf("MinOS = %v, want 14.0", tgt.MinOS)
	}
	if !tgt.Valid() {
		t.Error("Valid() = false for a well-formed target")
	}
	if !tgt.Wide() {
		t.Error("Wide() = false for arm64")
	}
	if tgt.Magic() != macho.MH_MAGIC_64 {
		t.Errorf("Magic() = %v, want MH_MAGIC_64", tgt.Magic())
	}
}

func TestParseTargetEnvironments(t *testing.T) {
	cases := []struct {
		triple string
		want   macho.Platform
	}{
		{"arm64-apple-ios17.0", macho.PlatformIOS},
		{"arm64-apple-ios17.0-simulator", macho.PlatformIOSSimulator},
		{"arm64-apple-ios17.0-macabi", macho.PlatformMacCatalyst},
		{"x86_64-apple-tvos17.0-simulator", macho.PlatformTVOSSimulator},
		{"arm64-apple-watchos10.0", macho.PlatformWatchOS},
		{"arm64-apple-driverkit23.0", macho.PlatformDriverKit},
		{"arm64-apple-macosx14.0", macho.PlatformMacOS}, // pre-Xcode-15 spelling
	}
	for _, c := range cases {
		t.Run(c.triple, func(t *testing.T) {
			tgt, err := macho.ParseTarget(c.triple)
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", c.triple, err)
			}
			if tgt.Platform != c.want {
				t.Errorf("Platform = %v, want %v", tgt.Platform, c.want)
			}
		})
	}
}

func TestParseTargetRejectsBad(t *testing.T) {
	cases := []string{
		"arm64-apple",                  // too few components
		"arm64-apple-macos-extra-parts", // too many
		"riscv64-apple-macos14.0",      // unknown arch
		"arm64-microsoft-macos14.0",    // unknown vendor
		"arm64-apple-plan9",            // unknown os
		"arm64-apple-macos99.99.99.99", // malformed version (handled by ParseVersion)
	}
	for _, triple := range cases {
		t.Run(triple, func(t *testing.T) {
			if _, err := macho.ParseTarget(triple); err == nil {
				t.Errorf("ParseTarget(%q) succeeded, want an error", triple)
			}
		})
	}
}

func TestArchNameRoundTrip(t *testing.T) {
	names := []string{"arm64", "arm64e", "x86_64", "x86_64h"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			cpu, sub, ok := macho.ParseArch(name)
			if !ok {
				t.Fatalf("ParseArch(%q) failed", name)
			}
			if got := macho.ArchName(cpu, sub); got != name {
				t.Errorf("ArchName round trip = %q, want %q", got, name)
			}
		})
	}
}

func TestParseArchUnknown(t *testing.T) {
	if _, _, ok := macho.ParseArch("not_a_real_arch"); ok {
		t.Error("ParseArch accepted a nonexistent architecture")
	}
}

func TestSubCPUBaseStripsCapabilities(t *testing.T) {
	e := macho.ARM64EWithPtrAuth(0, false)
	if e.Base() != macho.CPU_SUBTYPE_ARM64E {
		t.Errorf("Base() = %v, want CPU_SUBTYPE_ARM64E", e.Base())
	}
	if e.Caps() == 0 {
		t.Error("Caps() = 0, want the ptrauth capability bits preserved")
	}
	v, versioned := e.PtrAuthVersion()
	if !versioned {
		t.Error("PtrAuthVersion reports unversioned for a versioned subtype")
	}
	if v != 0 {
		t.Errorf("PtrAuthVersion = %d, want 0", v)
	}
}

func TestMagicWidthEndian(t *testing.T) {
	cases := []struct {
		m      macho.Magic
		wide   bool
		endian macho.Endian
	}{
		{macho.MH_MAGIC, false, macho.LittleEndian},
		{macho.MH_CIGAM, false, macho.BigEndian},
		{macho.MH_MAGIC_64, true, macho.LittleEndian},
		{macho.MH_CIGAM_64, true, macho.BigEndian},
	}
	for _, c := range cases {
		if !c.m.Valid() {
			t.Errorf("%v.Valid() = false", c.m)
		}
		if got := c.m.Width().Wide(); got != c.wide {
			t.Errorf("%v.Width().Wide() = %v, want %v", c.m, got, c.wide)
		}
		if got := c.m.Endian(); got != c.endian {
			t.Errorf("%v.Endian() = %v, want %v", c.m, got, c.endian)
		}
	}
	if macho.Magic(0xdeadbeef).Valid() {
		t.Error("an arbitrary value reported as a valid magic")
	}
}

func TestIsAndIsFat(t *testing.T) {
	thin := []byte{0xcf, 0xfa, 0xed, 0xfe} // MH_MAGIC_64, little-endian
	thin = append(thin, make([]byte, 28)...)
	if !macho.Is(thin) {
		t.Error("Is() = false for a thin MH_MAGIC_64 header")
	}
	if macho.IsFat(thin) {
		t.Error("IsFat() = true for a thin header")
	}

	fat := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02} // FAT_MAGIC, nfat_arch=2
	if !macho.IsFat(fat) {
		t.Error("IsFat() = false for a FAT_MAGIC header with a plausible nfat_arch")
	}
	if macho.Is(fat) {
		t.Error("Is() = true for a fat header")
	}

	// 0xCAFEBABE is also the Java class file magic; a huge nfat_arch is what
	// tells them apart.
	javaClass := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x34, 0x00, 0x00}
	if macho.IsFat(javaClass) {
		t.Error("IsFat() = true for a Java class file magic")
	}

	if macho.Is(nil) || macho.IsFat(nil) {
		t.Error("Is/IsFat accepted a nil/empty header")
	}
}

func TestSecNameValidity(t *testing.T) {
	if !macho.Sec(macho.SEG_TEXT, macho.SECT_TEXT).Valid() {
		t.Error("__TEXT,__text should be valid")
	}
	if macho.Sec("", macho.SECT_TEXT).Valid() {
		t.Error("empty segment name should be invalid")
	}
	longName := "this_name_is_definitely_longer_than_sixteen_bytes"
	if macho.Sec(longName, macho.SECT_TEXT).Valid() {
		t.Error("a segment name over 16 bytes should be invalid")
	}
	if !macho.ValidName("__TEXT") {
		t.Error("__TEXT should be a valid 16-byte-field name")
	}
	if macho.ValidName("exactly_seventeen") {
		t.Error("a 17-byte name should not fit the 16-byte field")
	}
}

func TestVersionParsing(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"14", "14.0"},
		{"14.5", "14.5"},
		{"14.5.2", "14.5.2"}, // patch is shown only when non-zero
	}
	for _, c := range cases {
		v, err := macho.ParseVersion(c.in)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", c.in, err)
		}
		if got := v.String(); got != c.want {
			t.Errorf("ParseVersion(%q).String() = %q, want %q", c.in, got, c.want)
		}
	}
	v, err := macho.ParseVersion("14.5.2")
	if err != nil {
		t.Fatalf("ParseVersion: %v", err)
	}
	if v.Major() != 14 || v.Minor() != 5 || v.Patch() != 2 {
		t.Errorf("14.5.2 parsed as %d.%d.%d", v.Major(), v.Minor(), v.Patch())
	}

	for _, bad := range []string{"", "1.2.3.4", "abc", "70000", "1.300"} {
		if _, err := macho.ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) succeeded, want an error", bad)
		}
	}
}

func TestTargetStringAndArch(t *testing.T) {
	tgt, err := macho.ParseTarget("arm64e-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if tgt.Arch() != "arm64e" {
		t.Errorf("Arch() = %q, want arm64e", tgt.Arch())
	}
	s := tgt.String()
	if s == "" {
		t.Error("String() returned empty")
	}
}
