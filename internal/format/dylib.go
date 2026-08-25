package format

import (
	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// Dylib is struct dylib, the identification block inside a dylib_command.
type Dylib struct {
	Name           LCStr
	Timestamp      uint32
	CurrentVersion macho.Version
	CompatVersion  macho.Version
}

// DylibCmd is struct dylib_command: LC_ID_DYLIB, LC_LOAD_DYLIB,
// LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB, and
// LC_LAZY_LOAD_DYLIB all share it.
//
// Which of those commands a dylib appears under determines its position in the
// two-level namespace ordinal sequence, so the command must be preserved, not
// normalized to LC_LOAD_DYLIB on a round-trip.
type DylibCmd struct {
	Cmd     macho.LoadCmd
	CmdSize uint32
	Dylib   Dylib
}

// DylibCmdSize is the fixed part of struct dylib_command; the pathname string
// follows and is counted in CmdSize.
const DylibCmdSize = 24

func (d *DylibCmd) Decode(c *binio.Cursor) error {
	d.Cmd = macho.LoadCmd(c.U32())
	d.CmdSize = c.U32()
	d.Dylib.Name = LCStr(c.U32())
	d.Dylib.Timestamp = c.U32()
	d.Dylib.CurrentVersion = macho.Version(c.U32())
	d.Dylib.CompatVersion = macho.Version(c.U32())
	return c.Err()
}

func (d *DylibCmd) Encode(b *binio.Buf) {
	b.U32(uint32(d.Cmd))
	b.U32(d.CmdSize)
	b.U32(uint32(d.Dylib.Name))
	b.U32(d.Dylib.Timestamp)
	b.U32(uint32(d.Dylib.CurrentVersion))
	b.U32(uint32(d.Dylib.CompatVersion))
}

// DylinkerCmd is struct dylinker_command, shared by LC_LOAD_DYLINKER,
// LC_ID_DYLINKER, and LC_DYLD_ENVIRONMENT. It is also the shape of
// LC_RPATH, LC_SUB_FRAMEWORK, LC_SUB_CLIENT, LC_SUB_UMBRELLA, and
// LC_SUB_LIBRARY: a header plus one lc_str.
type DylinkerCmd struct {
	Cmd     macho.LoadCmd
	CmdSize uint32
	Name    LCStr
}

// DylinkerCmdSize is the fixed part; the string follows.
const DylinkerCmdSize = 12

func (d *DylinkerCmd) Decode(c *binio.Cursor) error {
	d.Cmd = macho.LoadCmd(c.U32())
	d.CmdSize = c.U32()
	d.Name = LCStr(c.U32())
	return c.Err()
}

func (d *DylinkerCmd) Encode(b *binio.Buf) {
	b.U32(uint32(d.Cmd))
	b.U32(d.CmdSize)
	b.U32(uint32(d.Name))
}

// BuildVersion is struct build_version_command, without the tool array.
//
// LC_VERSION_MIN_* is read but never written by this tree: it cannot express
// Mac Catalyst, the simulators, DriverKit, or a tool version, so writing it
// would silently lose information the platform field carries.
type BuildVersion struct {
	Cmd      macho.LoadCmd
	CmdSize  uint32
	Platform macho.Platform
	MinOS    macho.Version
	SDK      macho.Version
	NTools   uint32
}

// BuildVersionSize is the fixed part of struct build_version_command;
// NTools BuildToolVersion entries follow and are counted in CmdSize.
const BuildVersionSize = 24

func (v *BuildVersion) Decode(c *binio.Cursor) error {
	v.Cmd = macho.LoadCmd(c.U32())
	v.CmdSize = c.U32()
	v.Platform = macho.Platform(c.U32())
	v.MinOS = macho.Version(c.U32())
	v.SDK = macho.Version(c.U32())
	v.NTools = c.U32()
	return c.Err()
}

func (v *BuildVersion) Encode(b *binio.Buf) {
	b.U32(uint32(v.Cmd))
	b.U32(v.CmdSize)
	b.U32(uint32(v.Platform))
	b.U32(uint32(v.MinOS))
	b.U32(uint32(v.SDK))
	b.U32(v.NTools)
}

// TotalSize returns the full cmdsize for a build version command with NTools
// tool entries.
func (v *BuildVersion) TotalSize() int {
	return BuildVersionSize + int(v.NTools)*BuildToolVersionSize
}

// BuildToolVersion is struct build_tool_version.
type BuildToolVersion struct {
	Tool    macho.Tool
	Version macho.Version
}

// BuildToolVersionSize is the on-disk size of one tool entry.
const BuildToolVersionSize = 8

func (t *BuildToolVersion) Decode(c *binio.Cursor) error {
	t.Tool = macho.Tool(c.U32())
	t.Version = macho.Version(c.U32())
	return c.Err()
}

func (t *BuildToolVersion) Encode(b *binio.Buf) {
	b.U32(uint32(t.Tool))
	b.U32(uint32(t.Version))
}

// VersionMin is struct version_min_command, for LC_VERSION_MIN_MACOSX and its
// siblings. Decode only: nothing in this tree emits one.
type VersionMin struct {
	Cmd     macho.LoadCmd
	CmdSize uint32
	Version macho.Version
	SDK     macho.Version
}

// VersionMinSize is the fixed size of struct version_min_command.
const VersionMinSize = 16

func (v *VersionMin) Decode(c *binio.Cursor) error {
	v.Cmd = macho.LoadCmd(c.U32())
	v.CmdSize = c.U32()
	v.Version = macho.Version(c.U32())
	v.SDK = macho.Version(c.U32())
	return c.Err()
}

// Platform infers the platform a version_min command implies, so a file
// carrying only the legacy command can still produce a macho.Target.
func (v *VersionMin) Platform() macho.Platform {
	switch v.Cmd {
	case macho.LC_VERSION_MIN_MACOSX:
		return macho.PlatformMacOS
	case macho.LC_VERSION_MIN_IPHONEOS:
		return macho.PlatformIOS
	case macho.LC_VERSION_MIN_TVOS:
		return macho.PlatformTVOS
	case macho.LC_VERSION_MIN_WATCHOS:
		return macho.PlatformWatchOS
	}
	return macho.PlatformUnknown
}

// LinkerOptionCmd is struct linker_option_command, used only in MH_OBJECT.
// Count NUL-terminated strings follow the fixed part; they are the argv a
// compiler wants forwarded to the linker, such as -framework Foundation.
type LinkerOptionCmd struct {
	Cmd     macho.LoadCmd
	CmdSize uint32
	Count   uint32
}

// LinkerOptionCmdSize is the fixed part; the strings follow.
const LinkerOptionCmdSize = 12

func (l *LinkerOptionCmd) Decode(c *binio.Cursor) error {
	l.Cmd = macho.LoadCmd(c.U32())
	l.CmdSize = c.U32()
	l.Count = c.U32()
	return c.Err()
}

func (l *LinkerOptionCmd) Encode(b *binio.Buf) {
	b.U32(uint32(l.Cmd))
	b.U32(l.CmdSize)
	b.U32(l.Count)
}