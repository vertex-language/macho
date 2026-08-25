package macho

import (
	"fmt"
	"strconv"
	"strings"
)

// Platform is the platform field of LC_BUILD_VERSION.
//
// A simulator and a device are distinct platforms, not a flag on one platform.
// So is Mac Catalyst. Collapsing them loses the distinction the linker needs
// to pick the right .tbd target.
type Platform uint32

const (
	PlatformUnknown           Platform = 0
	PlatformMacOS             Platform = 1
	PlatformIOS               Platform = 2
	PlatformTVOS              Platform = 3
	PlatformWatchOS           Platform = 4
	PlatformBridgeOS          Platform = 5
	PlatformMacCatalyst       Platform = 6
	PlatformIOSSimulator      Platform = 7
	PlatformTVOSSimulator     Platform = 8
	PlatformWatchOSSimulator  Platform = 9
	PlatformDriverKit         Platform = 10
	PlatformVisionOS          Platform = 11
	PlatformVisionOSSimulator Platform = 12
	PlatformFirmware          Platform = 13
	PlatformSEPOS             Platform = 14
)

// Simulator reports whether p is a simulator platform.
func (p Platform) Simulator() bool {
	switch p {
	case PlatformIOSSimulator, PlatformTVOSSimulator,
		PlatformWatchOSSimulator, PlatformVisionOSSimulator:
		return true
	}
	return false
}

func (p Platform) String() string {
	switch p {
	case PlatformMacOS:
		return "macos"
	case PlatformIOS:
		return "ios"
	case PlatformTVOS:
		return "tvos"
	case PlatformWatchOS:
		return "watchos"
	case PlatformBridgeOS:
		return "bridgeos"
	case PlatformMacCatalyst:
		return "maccatalyst"
	case PlatformIOSSimulator:
		return "ios-simulator"
	case PlatformTVOSSimulator:
		return "tvos-simulator"
	case PlatformWatchOSSimulator:
		return "watchos-simulator"
	case PlatformDriverKit:
		return "driverkit"
	case PlatformVisionOS:
		return "xros"
	case PlatformVisionOSSimulator:
		return "xros-simulator"
	case PlatformFirmware:
		return "firmware"
	case PlatformSEPOS:
		return "sepos"
	}
	return "platform(?)"
}

// Tool is the tool field of a build_tool_version entry.
type Tool uint32

const (
	ToolClang Tool = 1
	ToolSwift Tool = 2
	ToolLD    Tool = 3
	ToolLLD   Tool = 4
)

func (t Tool) String() string {
	switch t {
	case ToolClang:
		return "clang"
	case ToolSwift:
		return "swift"
	case ToolLD:
		return "ld"
	case ToolLLD:
		return "lld"
	}
	return "tool(?)"
}

// Version is the nibble-packed xxxx.yy.zz encoding used by LC_BUILD_VERSION's
// minos and sdk fields, by build_tool_version.version, and by a dylib's
// current and compatibility versions.
//
// ParseVersion and String are the only conversions; the raw uint32 is never
// handled outside them.
type Version uint32

// MakeVersion packs a version. Minor and patch are truncated to 8 bits.
func MakeVersion(major uint16, minor, patch uint8) Version {
	return Version(uint32(major)<<16 | uint32(minor)<<8 | uint32(patch))
}

func (v Version) Major() uint16 { return uint16(v >> 16) }
func (v Version) Minor() uint8  { return uint8(v >> 8) }
func (v Version) Patch() uint8  { return uint8(v) }

// String renders v as X.Y, or X.Y.Z when the patch component is non-zero.
// This matches what otool -l and vtool print.
func (v Version) String() string {
	if p := v.Patch(); p != 0 {
		return fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), p)
	}
	return fmt.Sprintf("%d.%d", v.Major(), v.Minor())
}

// ParseVersion parses "X", "X.Y", or "X.Y.Z".
func ParseVersion(s string) (Version, error) {
	if s == "" {
		return 0, fmt.Errorf("macho: empty version")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return 0, fmt.Errorf("macho: version %q has too many components", s)
	}
	var n [3]uint64
	limits := [3]uint64{0xffff, 0xff, 0xff}
	for i, p := range parts {
		u, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("macho: bad version %q: %w", s, err)
		}
		if u > limits[i] {
			return 0, fmt.Errorf("macho: version %q: component %d does not fit", s, i)
		}
		n[i] = u
	}
	return MakeVersion(uint16(n[0]), uint8(n[1]), uint8(n[2])), nil
}

// MustParseVersion is ParseVersion for constants known good at build time.
func MustParseVersion(s string) Version {
	v, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}

// BuildVersion is the payload of LC_BUILD_VERSION, minus the tool list.
//
// obj.Options.Build must be set: a platform-less object makes every
// downstream linker guess, and Xcode 15's linker warns about exactly that.
type BuildVersion struct {
	Platform Platform
	MinOS    Version
	SDK      Version
}

// Zero reports whether bv was left at its zero value.
func (bv BuildVersion) Zero() bool { return bv == BuildVersion{} }