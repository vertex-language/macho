// Package obj reads and writes MH_OBJECT files: the relocatable objects a
// compiler emits and a linker consumes.
//
// Read and write are separate type families. A *File is immutable after Open or
// NewFile; a Writer under construction is a different type with different
// invariants, and neither converts into the other. The two halves share only
// internal/format, which defines every on-disk structure exactly once.
//
// # Parsing one slice of a universal file
//
// NewFile takes a binio.Extent rather than a []byte so that one member of a fat
// file parses in place. The extent's reader is the whole file, but every offset
// inside it is relative to the slice's base and cannot reach outside it, so a
// member cannot read its neighbour and nothing has to be copied out first. Open
// is the convenience wrapper for a thin file on disk.
//
// # What "immutable" buys
//
// Symbols are decoded once and cached, so *Symbol pointer identity is stable
// for the life of the File. link relies on that: a symbol is a map key during
// resolution, and re-decoding would produce equal-but-distinct pointers.
package obj

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
)

// Read-side errors. The writer's errors are declared in writer.go.
var (
	// ErrNotObject means a file that is not MH_OBJECT reached the object
	// reader — most often a linked image, which needs image.Read instead.
	ErrNotObject = errors.New("obj: not an MH_OBJECT file")

	// ErrBadLoadCommand means a cmdsize was too small to contain its own
	// header, was misaligned for the file's width, or ran past the end of the
	// load-command region. All three are the same bug from a walk's point of
	// view: the next command cannot be located.
	ErrBadLoadCommand = errors.New("obj: invalid, unaligned, or non-advancing cmdsize")

	// ErrNoSymbolTable means a lookup needed a symbol table the file does not
	// have. An object with relocations but no LC_SYMTAB is malformed, but a
	// stripped object with neither is legal, so this is an error the caller
	// may reasonably ignore.
	ErrNoSymbolTable = errors.New("obj: file has no symbol table")

	// ErrBadSection means a section header could not be trusted: an alignment
	// that cannot be shifted, or a section array that does not fit its
	// segment command.
	ErrBadSection = errors.New("obj: invalid section header")
)

// File is a parsed MH_OBJECT file.
//
// Every field is filled in by Open or NewFile and is not written again.
// Symbols, relocations, and __LINKEDIT side tables are decoded on demand and
// cached, which is the only mutation a File performs after construction.
type File struct {
	ext    binio.Extent
	closer io.Closer

	// sliceBase is the offset of this Mach-O within its enclosing file: zero
	// for a thin file, the fat slice's offset for one member of a universal
	// file. Every file offset read out of a load command is relative to the
	// slice, not to the enclosing file, so this is needed only to report an
	// offset a human can find with a hex editor.
	//
	// This is the field the tree's README calls out as missing. It is declared
	// here, and base() below is the only reader of it.
	sliceBase int64

	hdr format.MachHeader

	// Cmds is every load command in file order, including ones this package
	// does not interpret. A caller that needs a command obj ignores can decode
	// it from Data with internal/format.
	Cmds []LoadCmd

	// Sections is every section in every segment, flattened, in the order the
	// section array declares them. Index i holds n_sect ordinal i+1.
	//
	// An MH_OBJECT file has a single unnamed segment with vmaddr 0 that holds
	// every section, so flattening loses nothing; Segment exposes the raw
	// command for the rare caller that wants it.
	Sections []*Section

	seg *Segment

	symtab   *format.Symtab
	dysymtab *format.Dysymtab
	build    *BuildInfo
	uuid     *[16]byte

	// linkedit maps a linkedit_data_command's cmd to its payload descriptor.
	// One structure serves eight different commands; only the cmd tells them
	// apart, so the map is keyed by it.
	linkedit map[macho.LoadCmd]format.LinkeditData

	symOnce sync.Once
	syms    []*Symbol
	symErr  error

	indOnce sync.Once
	indSyms []uint32
	indErr  error
}

// LoadCmd is one load command located within the file.
//
// Data is the command's full bytes including its eight-byte header, which is
// what an lc_str offset is measured from. It aliases the File's copy of the
// load-command region and must not be mutated.
type LoadCmd struct {
	Cmd    macho.LoadCmd
	Size   uint32
	Offset int64 // from the start of the slice, not of the enclosing file
	Data   []byte
}

// Segment is the decoded segment load command.
//
// In an MH_OBJECT file there is exactly one, its name is empty, and its vmaddr
// is zero; section addresses are therefore already offsets from the start of
// the segment's contents. Nothing in this package depends on that, so a
// non-conforming object still reads.
type Segment struct {
	Name     string
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	MaxProt  macho.Prot
	InitProt macho.Prot
	Flags    macho.SegFlags
	Sections []*Section
}

// BuildInfo is the decoded LC_BUILD_VERSION, including its tool list.
type BuildInfo struct {
	Platform macho.Platform
	MinOS    macho.Version
	SDK      macho.Version
	Tools    []ToolVersion

	// Legacy is true when this was reconstructed from an LC_VERSION_MIN_*
	// command rather than read from LC_BUILD_VERSION. A legacy command cannot
	// express Mac Catalyst, the simulators, or DriverKit, so a platform
	// derived from one is a best guess and SDK may be zero.
	Legacy bool
}

// ToolVersion is one build_tool_version entry.
type ToolVersion struct {
	Tool    macho.Tool
	Version macho.Version
}

// Open opens a thin Mach-O object file. The returned File owns the descriptor
// and Close releases it.
func Open(name string) (*File, error) {
	bf, err := binio.Open(name)
	if err != nil {
		return nil, err
	}
	f, err := NewFile(bf.Extent())
	if err != nil {
		bf.Close()
		return nil, err
	}
	f.closer = bf
	return f, nil
}

// NewFile parses an object out of an extent.
//
// The extent may be a whole file or one slice of a universal file; nothing
// below this point can tell the difference, which is the point. Closing the
// result does not close whatever the extent reads from.
func NewFile(ext binio.Extent) (*File, error) {
	if !ext.Valid() {
		return nil, fmt.Errorf("obj: NewFile called with a zero Extent")
	}

	// Read enough for the widest header. Head returns short rather than
	// failing, so a truncated file reaches DecodeHeader and gets a header
	// error instead of a bounds error with no context.
	head, err := ext.Head(format.HeaderSize(macho.Width64))
	if err != nil {
		return nil, err
	}
	if macho.IsFat(head) {
		return nil, macho.ErrFatFile
	}
	h, err := format.DecodeHeader(head, ext.Base())
	if err != nil {
		return nil, err
	}
	if h.FileType != macho.MH_OBJECT {
		return nil, fmt.Errorf("%w: filetype is %v", ErrNotObject, h.FileType)
	}

	f := &File{
		ext:       ext,
		sliceBase: ext.Base(),
		hdr:       *h,
		linkedit:  make(map[macho.LoadCmd]format.LinkeditData),
	}

	// Reject a declared command count that cannot fit its declared region
	// before reading anything, so a hostile ncmds fails on arithmetic.
	if uint64(h.NCmds)*uint64(format.LoadCmdHeaderSize) > uint64(h.SizeOfCmds) {
		return nil, fmt.Errorf("%w: %d commands do not fit in %d bytes",
			ErrBadLoadCommand, h.NCmds, h.SizeOfCmds)
	}

	cmds, err := ext.Read(int64(h.Size()), int64(h.SizeOfCmds))
	if err != nil {
		return nil, err
	}
	if err := f.walk(cmds); err != nil {
		return nil, err
	}
	if err := f.index(); err != nil {
		return nil, err
	}
	return f, nil
}

// Close releases the underlying file if this File opened it.
func (f *File) Close() error {
	if f.closer != nil {
		return f.closer.Close()
	}
	return nil
}

// base returns the offset of this Mach-O within its enclosing file. It is zero
// for a thin file and the slice offset for one member of a universal file.
func (f *File) base() int64 { return f.sliceBase }

// Base is base for callers outside the package — a fat member reporting a file
// offset a human can find.
func (f *File) Base() int64 { return f.sliceBase }

// Size returns the length of this Mach-O, which for a fat member is the slice
// size rather than the whole file.
func (f *File) Size() int64 { return f.ext.Size() }

// Header field accessors. The header struct itself stays unexported: it is an
// internal/format type, and exposing it would put an internal package in this
// package's API surface.
func (f *File) Magic() macho.Magic       { return f.hdr.Magic }
func (f *File) Width() macho.Width       { return f.hdr.Magic.Width() }
func (f *File) Endian() macho.Endian     { return f.hdr.Magic.Endian() }
func (f *File) CPU() macho.CPU           { return f.hdr.CPU }
func (f *File) SubCPU() macho.SubCPU     { return f.hdr.SubCPU }
func (f *File) FileType() macho.FileType { return f.hdr.FileType }
func (f *File) Flags() macho.Flags       { return f.hdr.Flags }

// Arch returns the toolchain arch name for this file, e.g. "arm64e".
func (f *File) Arch() string { return macho.ArchName(f.hdr.CPU, f.hdr.SubCPU) }

// Subsections reports whether MH_SUBSECTIONS_VIA_SYMBOLS is set, which is what
// makes Section.Atoms meaningful.
func (f *File) Subsections() bool {
	return f.hdr.Flags.Has(macho.MH_SUBSECTIONS_VIA_SYMBOLS)
}

// Segment returns the file's segment command, or nil if it has none.
//
// An MH_OBJECT file has exactly one. Sections flattens it; this is for the
// caller that wants maxprot, the flags, or the raw file extent.
func (f *File) Segment() *Segment { return f.seg }

// Section returns the section with the given (segment, section) identity, or
// nil.
//
// There is no lookup by bare section name, here or anywhere else in the tree:
// __DATA,__const and __DATA_CONST,__const are different sections and a bare
// name cannot tell them apart.
func (f *File) Section(n macho.SecName) *Section {
	for _, s := range f.Sections {
		if s.Segment == n.Segment && s.Name == n.Section {
			return s
		}
	}
	return nil
}

// SectionAt returns the section with the given n_sect ordinal, which is
// 1-based, or nil if the ordinal is out of range.
//
// NO_SECT (0) is not an error here; it returns nil, because a symbol that
// carries it is legitimately not in any section.
func (f *File) SectionAt(ordinal uint8) *Section {
	if ordinal == macho.NO_SECT || int(ordinal) > len(f.Sections) {
		return nil
	}
	return f.Sections[ordinal-1]
}

// Build returns the file's build version, and whether it had one.
//
// The result is reconstructed from LC_VERSION_MIN_* when that is all the file
// carries, with Legacy set. LC_BUILD_VERSION is preferred whenever both are
// present, which happens in objects built by older assemblers under a newer
// deployment target.
func (f *File) Build() (BuildInfo, bool) {
	if f.build == nil {
		return BuildInfo{}, false
	}
	return *f.build, true
}

// UUID returns the LC_UUID payload and whether the file carried one. Compilers
// do not normally emit LC_UUID in objects; the linker generates it.
func (f *File) UUID() ([16]byte, bool) {
	if f.uuid == nil {
		return [16]byte{}, false
	}
	return *f.uuid, true
}

// Target returns the macho.Target this object was compiled for.
//
// Endianness comes from the magic and width from the CPU, so neither can
// disagree with the file. Platform and versions come from the build command
// and are zero when the file has none — which is exactly the case
// Options.Build refuses to produce on the write side, because it makes every
// downstream linker guess.
func (f *File) Target() macho.Target {
	t := macho.Target{
		CPU:    f.hdr.CPU,
		SubCPU: f.hdr.SubCPU,
		Endian: f.hdr.Magic.Endian(),
	}
	if f.build != nil {
		t.Platform = f.build.Platform
		t.MinOS = f.build.MinOS
		t.SDK = f.build.SDK
	}
	return t
}

// walk splits the load-command region into commands without interpreting any
// of them.
//
// Three properties are checked per command, and together they are what turns a
// crafted cmdsize into an error rather than a hang or an overrun: the size must
// contain the header, it must be aligned to the width's requirement, and it
// must fit in what is left. The first two are format.LoadCmdHeader.Valid; the
// third is a bounds question and belongs here, where the region's length is
// known. A cmdsize of at least LoadCmdHeaderSize is also what guarantees the
// loop advances.
func (f *File) walk(data []byte) error {
	var (
		w    = f.Width()
		ord  = f.Endian().Order()
		hlen = int64(f.hdr.Size())
		off  int
	)
	for i := uint32(0); i < f.hdr.NCmds; i++ {
		if off+format.LoadCmdHeaderSize > len(data) {
			return fmt.Errorf("%w: command %d begins at %d, past the %d-byte region",
				ErrBadLoadCommand, i, off, len(data))
		}
		c := binio.NewCursorAt(data[off:], ord, f.sliceBase+hlen+int64(off))
		var h format.LoadCmdHeader
		if err := h.Decode(c); err != nil {
			return err
		}
		if !h.Valid(w) {
			return fmt.Errorf("%w: command %d (%v) has cmdsize %d, alignment %d",
				ErrBadLoadCommand, i, h.Cmd, h.CmdSize, format.CmdAlign(w))
		}
		if int64(h.CmdSize) > int64(len(data)-off) {
			return fmt.Errorf("%w: command %d (%v) claims %d bytes, %d remain",
				ErrBadLoadCommand, i, h.Cmd, h.CmdSize, len(data)-off)
		}
		f.Cmds = append(f.Cmds, LoadCmd{
			Cmd:    h.Cmd,
			Size:   h.CmdSize,
			Offset: hlen + int64(off),
			Data:   data[off : off+int(h.CmdSize)],
		})
		off += int(h.CmdSize)
	}
	return nil
}