package obj

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
)

// Find returns the first load command with the given cmd, or nil.
//
// The cmd is compared whole, including LC_REQ_DYLD: LC_DYLD_INFO and
// LC_DYLD_INFO_ONLY are the same base value distinguished only by that bit,
// and collapsing them would make a lookup for one match the other.
func (f *File) Find(cmd macho.LoadCmd) *LoadCmd {
	for i := range f.Cmds {
		if f.Cmds[i].Cmd == cmd {
			return &f.Cmds[i]
		}
	}
	return nil
}

// FindAll returns every load command with the given cmd, in file order.
func (f *File) FindAll(cmd macho.LoadCmd) []*LoadCmd {
	var out []*LoadCmd
	for i := range f.Cmds {
		if f.Cmds[i].Cmd == cmd {
			out = append(out, &f.Cmds[i])
		}
	}
	return out
}

// cursor returns a cursor over one load command's bytes, in the file's byte
// order, based so that offsets in error messages are file offsets.
func (f *File) cursor(c *LoadCmd) *binio.Cursor {
	return binio.NewCursorAt(c.Data, f.Endian().Order(), f.sliceBase+c.Offset)
}

// index interprets the commands this package understands.
//
// Commands it does not understand stay in Cmds and are otherwise ignored. That
// is correct for an object reader even for LC_REQ_DYLD commands: the bit means
// dyld must understand the command to run the image, and an MH_OBJECT is never
// run.
func (f *File) index() error {
	segCmd := macho.SegmentCmd(f.Width())

	for i := range f.Cmds {
		cmd := &f.Cmds[i]
		switch cmd.Cmd {

		case macho.LC_SEGMENT, macho.LC_SEGMENT_64:
			// A 32-bit segment command in a 64-bit file, or the reverse, is a
			// file whose two halves disagree about pointer width. Decoding it
			// with the header's width would read the wrong number of bytes
			// per field and produce plausible garbage.
			if cmd.Cmd != segCmd {
				return fmt.Errorf("%w: %v in a %v-bit file",
					ErrBadLoadCommand, cmd.Cmd, f.Width())
			}
			if f.seg != nil {
				return fmt.Errorf("%w: more than one segment in an MH_OBJECT file",
					ErrBadLoadCommand)
			}
			if err := f.readSegment(cmd); err != nil {
				return err
			}

		case macho.LC_SYMTAB:
			var st format.Symtab
			if err := st.Decode(f.cursor(cmd)); err != nil {
				return err
			}
			f.symtab = &st

		case macho.LC_DYSYMTAB:
			var dst format.Dysymtab
			if err := dst.Decode(f.cursor(cmd)); err != nil {
				return err
			}
			f.dysymtab = &dst

		case macho.LC_BUILD_VERSION:
			bi, err := f.readBuildVersion(cmd)
			if err != nil {
				return err
			}
			// LC_BUILD_VERSION always wins over a legacy command, whichever
			// order they appear in.
			f.build = bi

		case macho.LC_VERSION_MIN_MACOSX, macho.LC_VERSION_MIN_IPHONEOS,
			macho.LC_VERSION_MIN_TVOS, macho.LC_VERSION_MIN_WATCHOS:
			if f.build != nil && !f.build.Legacy {
				break
			}
			var vm format.VersionMin
			if err := vm.Decode(f.cursor(cmd)); err != nil {
				return err
			}
			f.build = &BuildInfo{
				Platform: vm.Platform(),
				MinOS:    vm.Version,
				SDK:      vm.SDK,
				Legacy:   true,
			}

		case macho.LC_UUID:
			var u format.UUID
			if err := u.Decode(f.cursor(cmd)); err != nil {
				return err
			}
			id := u.UUID
			f.uuid = &id

		case macho.LC_DATA_IN_CODE, macho.LC_LINKER_OPTIMIZATION_HINT,
			macho.LC_FUNCTION_STARTS, macho.LC_SEGMENT_SPLIT_INFO,
			macho.LC_CODE_SIGNATURE:
			var ld format.LinkeditData
			if err := ld.Decode(f.cursor(cmd)); err != nil {
				return err
			}
			f.linkedit[cmd.Cmd] = ld
		}
	}
	return nil
}

// readSegment decodes the segment command and the section array that follows
// it in the same command.
func (f *File) readSegment(cmd *LoadCmd) error {
	w := f.Width()
	c := f.cursor(cmd)

	var sc format.SegmentCmd
	if err := sc.Decode(c, w); err != nil {
		return err
	}

	// The cursor now sits at the first section structure and its remaining
	// length is exactly the declared section array, because the cursor covers
	// only this command's bytes. Count therefore validates nsects against the
	// space the command actually reserved, before anything is allocated.
	n, ok := c.Count(uint64(sc.NSects), format.SectionSize(w), "sections")
	if !ok {
		return c.Err()
	}

	seg := &Segment{
		Name:     sc.Name,
		VMAddr:   sc.VMAddr,
		VMSize:   sc.VMSize,
		FileOff:  sc.FileOff,
		FileSize: sc.FileSize,
		MaxProt:  sc.MaxProt,
		InitProt: sc.InitProt,
		Flags:    sc.Flags,
	}

	for i := 0; i < n; i++ {
		var fs format.Section
		if err := fs.Decode(c, w); err != nil {
			return err
		}
		s, err := f.newSection(&fs, len(f.Sections)+1)
		if err != nil {
			return err
		}
		s.seg = seg
		seg.Sections = append(seg.Sections, s)
		f.Sections = append(f.Sections, s)
	}

	f.seg = seg
	return c.Err()
}

// readBuildVersion decodes LC_BUILD_VERSION and its trailing tool array.
func (f *File) readBuildVersion(cmd *LoadCmd) (*BuildInfo, error) {
	c := f.cursor(cmd)

	var bv format.BuildVersion
	if err := bv.Decode(c); err != nil {
		return nil, err
	}
	n, ok := c.Count(uint64(bv.NTools), format.BuildToolVersionSize, "build tools")
	if !ok {
		return nil, c.Err()
	}

	bi := &BuildInfo{Platform: bv.Platform, MinOS: bv.MinOS, SDK: bv.SDK}
	for i := 0; i < n; i++ {
		var tv format.BuildToolVersion
		if err := tv.Decode(c); err != nil {
			return nil, err
		}
		bi.Tools = append(bi.Tools, ToolVersion{Tool: tv.Tool, Version: tv.Version})
	}
	return bi, c.Err()
}

// linkeditBytes reads the __LINKEDIT payload of a linkedit_data_command.
//
// It returns nil with no error when the file has no such command or the
// command declares an empty payload, so a caller can treat "absent" and
// "empty" alike — which is what every caller of a side table wants.
func (f *File) linkeditBytes(cmd macho.LoadCmd) ([]byte, error) {
	ld, ok := f.linkedit[cmd]
	if !ok || ld.DataSize == 0 {
		return nil, nil
	}
	return f.ext.Read(int64(ld.DataOff), int64(ld.DataSize))
}