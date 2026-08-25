package macho

import (
	"fmt"
	"strings"
)

// Target is everything needed to decide the shape of one Mach-O file.
//
// Width is deliberately absent as a field. It is a function of CPU, so a
// Target that claims a 64-bit width for a 32-bit CPU cannot be constructed.
type Target struct {
	CPU      CPU
	SubCPU   SubCPU
	Platform Platform
	MinOS    Version
	SDK      Version
	Endian   Endian
}

// Width derives the pointer width from t.CPU.
func (t Target) Width() Width { return t.CPU.Width() }

// Wide reports whether t uses 64-bit pointers.
func (t Target) Wide() bool { return t.CPU.Wide() }

// Magic returns the header magic implied by t.
func (t Target) Magic() Magic {
	switch {
	case t.Wide() && t.Endian == BigEndian:
		return MH_CIGAM_64
	case t.Wide():
		return MH_MAGIC_64
	case t.Endian == BigEndian:
		return MH_CIGAM
	default:
		return MH_MAGIC
	}
}

// Arch returns the toolchain arch name, e.g. "arm64e".
func (t Target) Arch() string { return ArchName(t.CPU, t.SubCPU) }

// Build returns the LC_BUILD_VERSION payload for t.
func (t Target) Build() BuildVersion {
	return BuildVersion{Platform: t.Platform, MinOS: t.MinOS, SDK: t.SDK}
}

// Valid reports whether t is a target this tree can emit for.
func (t Target) Valid() bool {
	return t.CPU.Supported() &&
		t.Platform != PlatformUnknown &&
		t.Endian.Valid() &&
		t.MinOS != 0
}

// String renders t as "arm64e/macos/14.0/little/64".
func (t Target) String() string {
	return strings.Join([]string{
		t.Arch(), t.Platform.String(), t.MinOS.String(),
		t.Endian.String(), t.Width().String(),
	}, "/")
}

// ParseTarget parses an LLVM-style triple: <arch>-<vendor>-<os><version>
// optionally followed by an environment component.
//
// The environment decides the platform, and the resulting platforms are
// distinct values rather than a flag on one:
//
//	arm64-apple-ios17.0             -> PlatformIOS
//	arm64-apple-ios17.0-simulator   -> PlatformIOSSimulator
//	arm64-apple-ios17.0-macabi      -> PlatformMacCatalyst
//
// SDK is left zero; the caller sets it, since a triple does not carry one.
func ParseTarget(triple string) (Target, error) {
	parts := strings.Split(triple, "-")
	if len(parts) < 3 || len(parts) > 4 {
		return Target{}, fmt.Errorf("%w: %q is not <arch>-<vendor>-<os>[-<env>]",
			ErrInvalidTarget, triple)
	}

	cpu, sub, ok := ParseArch(parts[0])
	if !ok {
		return Target{}, fmt.Errorf("%w: unknown arch %q", ErrUnsupportedCPU, parts[0])
	}
	if v := parts[1]; v != "apple" && v != "unknown" {
		return Target{}, fmt.Errorf("%w: vendor %q is not apple", ErrInvalidTarget, v)
	}

	osName, verStr := splitOSVersion(parts[2])
	env := ""
	if len(parts) == 4 {
		env = parts[3]
	}

	plat, ok := platformFor(osName, env)
	if !ok {
		return Target{}, fmt.Errorf("%w: unknown os/env %q/%q",
			ErrInvalidTarget, osName, env)
	}

	var minOS Version
	if verStr != "" {
		v, err := ParseVersion(verStr)
		if err != nil {
			return Target{}, fmt.Errorf("%w: %v", ErrInvalidTarget, err)
		}
		minOS = v
	}

	return Target{
		CPU: cpu, SubCPU: sub, Platform: plat,
		MinOS: minOS, Endian: cpu.Endian(),
	}, nil
}

// splitOSVersion splits "macosx14.0" into ("macosx", "14.0").
func splitOSVersion(s string) (name, version string) {
	i := 0
	for i < len(s) && (s[i] < '0' || s[i] > '9') {
		i++
	}
	return s[:i], s[i:]
}

func platformFor(osName, env string) (Platform, bool) {
	switch env {
	case "macabi":
		if osName == "ios" {
			return PlatformMacCatalyst, true
		}
		return PlatformUnknown, false
	case "simulator":
		switch osName {
		case "ios":
			return PlatformIOSSimulator, true
		case "tvos":
			return PlatformTVOSSimulator, true
		case "watchos":
			return PlatformWatchOSSimulator, true
		case "xros", "visionos":
			return PlatformVisionOSSimulator, true
		}
		return PlatformUnknown, false
	case "":
		switch osName {
		case "macos", "macosx", "darwin":
			return PlatformMacOS, true
		case "ios":
			return PlatformIOS, true
		case "tvos":
			return PlatformTVOS, true
		case "watchos":
			return PlatformWatchOS, true
		case "bridgeos":
			return PlatformBridgeOS, true
		case "driverkit":
			return PlatformDriverKit, true
		case "xros", "visionos":
			return PlatformVisionOS, true
		}
	}
	return PlatformUnknown, false
}