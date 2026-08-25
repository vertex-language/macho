package tbd

import (
	"strconv"
	"strings"

	"github.com/vertex-language/macho"
)

// Target is one architecture-platform pair a stub library supports.
//
// v4 writes these as a single token — "arm64-macos", "x86_64-ios-simulator" —
// and filters every export list by them. v1 through v3 have a document-wide
// platform and a separate arch list, so their targets are the cross product;
// Stub.Targets is filled in either way and nothing downstream needs to know
// which version it came from.
type Target struct {
	// Arch is the toolchain arch name exactly as the file wrote it. It is kept
	// raw because a stub may name an architecture this tree has no constants
	// for — every SDK libSystem.tbd still lists i386 — and dropping those
	// entries silently would make a file look like it supports fewer targets
	// than it does.
	Arch string

	// Platform is the resolved platform, or PlatformUnknown.
	Platform macho.Platform

	// PlatformRaw is the platform token as written, including the "<6>" numeric
	// form.
	PlatformRaw string

	CPU    macho.CPU
	SubCPU macho.SubCPU

	// Known reports whether Arch resolved to a CPU and SubCPU this tree
	// understands. An unknown target can be listed and printed but never
	// matches.
	Known bool
}

func (t Target) String() string {
	if t.PlatformRaw == "" {
		return t.Arch
	}
	return t.Arch + "-" + t.PlatformRaw
}

// Matches reports whether this target serves the given link target.
//
// Matching is exact on both axes. There is no fallback from arm64e to arm64 as
// there is when picking a fat slice: a slice is a whole image and a compatible
// one still runs, but a stub is a promise about which symbols exist, and
// arm64e and arm64 builds of one library genuinely differ in what they export.
// Capability bits are masked because the ptrauth ABI version is not part of
// the arch's identity.
func (t Target) Matches(want macho.Target) bool {
	if !t.Known {
		return false
	}
	if t.CPU != want.CPU || t.SubCPU.Base() != want.SubCPU.Base() {
		return false
	}
	// A stub with no platform — a v1 file whose platform key was unreadable —
	// matches on architecture alone rather than never matching.
	if t.Platform == macho.PlatformUnknown {
		return true
	}
	return t.Platform == want.Platform
}

// parseTargetToken parses a v4 target such as "x86_64-ios-simulator".
//
// The split is on the first hyphen only. Every arch name is hyphen-free while
// several platform names are not, so anything after the first hyphen is the
// platform.
func parseTargetToken(s string) Target {
	s = strings.TrimSpace(s)
	arch, plat := s, ""
	if i := strings.IndexByte(s, '-'); i >= 0 {
		arch, plat = s[:i], s[i+1:]
	}
	t := Target{Arch: arch, PlatformRaw: plat, Platform: parsePlatform(plat)}
	t.CPU, t.SubCPU, t.Known = macho.ParseArch(arch)
	return t
}

// parsePlatform maps a platform token to a macho.Platform.
//
// The v4 names are exactly what macho.Platform.String emits, so the mapping is
// a scan over the known values rather than a second table that could drift
// from the first. The pre-v4 spellings and the numeric "<N>" form are handled
// on top of that.
func parsePlatform(s string) macho.Platform {
	s = strings.TrimSpace(s)
	if s == "" {
		return macho.PlatformUnknown
	}
	if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
		n, err := strconv.ParseUint(s[1:len(s)-1], 10, 32)
		if err != nil {
			return macho.PlatformUnknown
		}
		return macho.Platform(n)
	}
	switch s {
	// Pre-v4 spellings that differ from the v4 ones.
	case "macosx":
		return macho.PlatformMacOS
	case "iosmac", "uikitformac", "macCatalyst":
		return macho.PlatformMacCatalyst
	case "visionos":
		return macho.PlatformVisionOS
	}
	for p := macho.PlatformMacOS; p <= macho.PlatformSEPOS; p++ {
		if p.String() == s {
			return p
		}
	}
	return macho.PlatformUnknown
}

// crossTargets builds the target list for a pre-v4 document, whose archs and
// platform are declared separately.
func crossTargets(archs []string, plat macho.Platform, platRaw string) []Target {
	out := make([]Target, 0, len(archs))
	for _, a := range archs {
		t := Target{Arch: strings.TrimSpace(a), Platform: plat, PlatformRaw: platRaw}
		t.CPU, t.SubCPU, t.Known = macho.ParseArch(t.Arch)
		out = append(out, t)
	}
	return out
}