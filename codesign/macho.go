// macho.go
package codesign

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Mach-O magic numbers.
const (
	mhMagic64 uint32 = 0xfeedfacf // 64-bit, host-endian
	mhCigam64 uint32 = 0xcffaedfe // 64-bit, byte-swapped
	fatMagic  uint32 = 0xcafebabe // universal header (big-endian on disk)
	fatCigam  uint32 = 0xbebafeca
)

// Mach-O filetypes we care about.
const (
	mhExecute uint32 = 0x2
	mhDylib   uint32 = 0x6
	mhBundle  uint32 = 0x8
)

// Load command numbers.
const (
	lcSegment64     uint32 = 0x19
	lcCodeSignature uint32 = 0x1d
	lcReqDyld       uint32 = 0x80000000
)

// Slice is one architecture inside a (possibly fat) Mach-O image. For a thin
// file there is exactly one Slice covering the whole image.
type Slice struct {
	Offset    int64  // file offset of this slice within the outer image
	Size      int64  // size of this slice
	CPU       uint32 // cputype
	SubCPU    uint32 // cpusubtype
	Bytes     []byte // the slice's bytes (a sub-slice of the parent image)
	bigEndian bool

	header   machHeader
	loadCmds []loadCmd
	textOff  int64 // __TEXT fileoff (execSegBase)
	textSize int64 // __TEXT filesize (execSegLimit)
	linkEdit *segment64
	csCmd    *loadCmd // existing LC_CODE_SIGNATURE, if any
	isMain   bool
}

type machHeader struct {
	Magic      uint32
	CPU        uint32
	SubCPU     uint32
	FileType   uint32
	NCmds      uint32
	SizeOfCmds uint32
	Flags      uint32
	Reserved   uint32
}

type loadCmd struct {
	Cmd    uint32
	Size   uint32
	Offset int64 // offset of this command within the slice
}

type segment64 struct {
	Name     string
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	cmdOff   int64 // offset of the LC_SEGMENT_64 within the slice
}

// Image is a parsed Mach-O file: one or more architecture slices.
type Image struct {
	raw    []byte
	isFat  bool
	Slices []*Slice
}

func (s *Slice) order() binary.ByteOrder {
	if s.bigEndian {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Parse reads a Mach-O image (fat or thin) from raw bytes without copying the
// backing array; edits later operate in place on a grown copy.
func Parse(raw []byte) (*Image, error) {
	if len(raw) < 4 {
		return nil, errors.New("codesign: file too small")
	}
	magic := binary.BigEndian.Uint32(raw[:4])
	img := &Image{raw: raw}

	switch magic {
	case fatMagic, fatCigam:
		img.isFat = true
		if err := img.parseFat(raw); err != nil {
			return nil, err
		}
	default:
		sl, err := parseThin(raw, 0, int64(len(raw)))
		if err != nil {
			return nil, err
		}
		img.Slices = []*Slice{sl}
	}
	return img, nil
}

func (img *Image) parseFat(raw []byte) error {
	// fat_header: magic(4) + nfat_arch(4), both big-endian.
	if len(raw) < 8 {
		return errors.New("codesign: truncated fat header")
	}
	n := binary.BigEndian.Uint32(raw[4:8])
	const fatArchSize = 20 // cputype,cpusubtype,offset,size,align (5×uint32)
	off := 8
	for i := uint32(0); i < n; i++ {
		if off+fatArchSize > len(raw) {
			return errors.New("codesign: truncated fat_arch table")
		}
		cpu := binary.BigEndian.Uint32(raw[off:])
		sub := binary.BigEndian.Uint32(raw[off+4:])
		fo := int64(binary.BigEndian.Uint32(raw[off+8:]))
		fs := int64(binary.BigEndian.Uint32(raw[off+12:]))
		off += fatArchSize
		if fo+fs > int64(len(raw)) {
			return fmt.Errorf("codesign: fat slice %d out of range", i)
		}
		sl, err := parseThin(raw[fo:fo+fs], fo, fs)
		if err != nil {
			return fmt.Errorf("codesign: slice %d: %w", i, err)
		}
		sl.CPU, sl.SubCPU = cpu, sub
		img.Slices = append(img.Slices, sl)
	}
	return nil
}

func parseThin(b []byte, fileOff, size int64) (*Slice, error) {
	if len(b) < 32 {
		return nil, errors.New("codesign: truncated mach header")
	}
	magic := binary.LittleEndian.Uint32(b[:4])
	var bo binary.ByteOrder
	switch magic {
	case mhMagic64:
		bo = binary.LittleEndian
	case mhCigam64:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("codesign: unsupported magic 0x%08x (only 64-bit Mach-O supported)", binary.BigEndian.Uint32(b[:4]))
	}

	sl := &Slice{Offset: fileOff, Size: size, Bytes: b, bigEndian: bo == binary.BigEndian}
	h := &sl.header
	h.Magic = magic
	h.CPU = bo.Uint32(b[4:])
	h.SubCPU = bo.Uint32(b[8:])
	h.FileType = bo.Uint32(b[12:])
	h.NCmds = bo.Uint32(b[16:])
	h.SizeOfCmds = bo.Uint32(b[20:])
	h.Flags = bo.Uint32(b[24:])
	sl.CPU, sl.SubCPU = h.CPU, h.SubCPU
	sl.isMain = h.FileType == mhExecute

	const machHeader64Size = 32
	off := int64(machHeader64Size)
	for i := uint32(0); i < h.NCmds; i++ {
		if off+8 > int64(len(b)) {
			return nil, errors.New("codesign: load command past end of slice")
		}
		cmd := bo.Uint32(b[off:])
		csize := bo.Uint32(b[off+4:])
		if csize < 8 || off+int64(csize) > int64(len(b)) {
			return nil, fmt.Errorf("codesign: bad load command size %d", csize)
		}
		lc := loadCmd{Cmd: cmd, Size: csize, Offset: off}
		sl.loadCmds = append(sl.loadCmds, lc)

		switch cmd {
		case lcSegment64:
			seg := parseSegment64(b[off:off+int64(csize)], bo, off)
			switch seg.Name {
			case "__TEXT":
				sl.textOff = int64(seg.FileOff)
				sl.textSize = int64(seg.FileSize)
			case "__LINKEDIT":
				s := seg
				sl.linkEdit = &s
			}
		case lcCodeSignature:
			c := sl.loadCmds[len(sl.loadCmds)-1]
			sl.csCmd = &c
		}
		off += int64(csize)
	}
	if sl.linkEdit == nil {
		return nil, errors.New("codesign: no __LINKEDIT segment")
	}
	return sl, nil
}

func parseSegment64(b []byte, bo binary.ByteOrder, cmdOff int64) segment64 {
	name := cstr(b[8:24])
	return segment64{
		Name:     name,
		VMAddr:   bo.Uint64(b[24:]),
		VMSize:   bo.Uint64(b[32:]),
		FileOff:  bo.Uint64(b[40:]),
		FileSize: bo.Uint64(b[48:]),
		cmdOff:   cmdOff,
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// signatureRegionStart returns the file offset (within the slice) at which the
// signature data must begin: just past the end of all non-signature content.
func (s *Slice) signatureRegionStart() int64 {
	if s.csCmd != nil {
		bo := s.order()
		// linkedit_data_command: cmd,cmdsize,dataoff,datasize
		return int64(bo.Uint32(s.Bytes[s.csCmd.Offset+8:]))
	}
	return int64(s.linkEdit.FileOff + s.linkEdit.FileSize)
}

// PatchHeaders updates the load commands for the new signature size.
// MUST be called before page hashes are computed.
func (s *Slice) PatchHeaders(sigSize int, codeLimit int64) {
	bo := s.order()
	need := codeLimit + int64(sigSize)

	if s.csCmd != nil {
		off := s.csCmd.Offset
		bo.PutUint32(s.Bytes[off+8:], uint32(codeLimit))
		bo.PutUint32(s.Bytes[off+12:], uint32(sigSize))
	}

	if s.linkEdit != nil {
		leOff := s.linkEdit.cmdOff
		newFileSize := uint64(need) - s.linkEdit.FileOff
		// macOS requires __LINKEDIT vmsize to be page-aligned
		alignedVMSize := (newFileSize + 0x3FFF) &^ uint64(0x3FFF)
		
		bo.PutUint64(s.Bytes[leOff+32:], alignedVMSize) // vmsize
		bo.PutUint64(s.Bytes[leOff+48:], newFileSize)   // filesize
		
		s.linkEdit.FileSize = newFileSize
		s.linkEdit.VMSize = alignedVMSize
	}
}

// embedSignature simply appends the blob to the slice.
func (s *Slice) embedSignature(super []byte, codeLimit int64) error {
	need := codeLimit + int64(len(super))

	if need > int64(len(s.Bytes)) {
		grown := make([]byte, need)
		copy(grown, s.Bytes[:codeLimit])
		s.Bytes = grown
	} else {
		s.Bytes = s.Bytes[:need]
	}
	s.Size = need

	copy(s.Bytes[codeLimit:], super)
	return nil
}

// serialize returns the final image bytes after all slices have been signed.
func (img *Image) serialize() ([]byte, error) {
	if !img.isFat {
		return img.Slices[0].Bytes, nil
	}

	outLen := int64(0)
	for _, sl := range img.Slices {
		if end := sl.Offset + int64(len(sl.Bytes)); end > outLen {
			outLen = end
		}
	}

	out := make([]byte, outLen)
	copy(out, img.raw)

	for _, sl := range img.Slices {
		copy(out[sl.Offset:], sl.Bytes)
	}

	nArch := int(binary.BigEndian.Uint32(out[4:8]))
	for i := 0; i < nArch; i++ {
		archOff := 8 + i*20
		fo := int64(binary.BigEndian.Uint32(out[archOff+8:]))
		for _, sl := range img.Slices {
			if sl.Offset == fo {
				binary.BigEndian.PutUint32(out[archOff+12:], uint32(len(sl.Bytes)))
				break
			}
		}
	}

	return out, nil
}

func (s *Slice) hasReservedSignatureSpace() bool { return s.csCmd != nil }

// ── Format / arch helpers ─────────────────────────────────────────────────────

// ArchString returns a human-readable CPU architecture name for this slice.
func (s *Slice) ArchString() string { return cpuTypeName(s.CPU) }

// FormatString returns a human-readable image format description.
// Examples: "Mach-O thin (arm64)", "Mach-O universal (arm64 x86_64)".
func (img *Image) FormatString() string {
	if !img.isFat {
		return fmt.Sprintf("Mach-O thin (%s)", img.Slices[0].ArchString())
	}
	archs := make([]string, len(img.Slices))
	for i, sl := range img.Slices {
		archs[i] = sl.ArchString()
	}
	return fmt.Sprintf("Mach-O universal (%s)", strings.Join(archs, " "))
}

// ── -vvv: full header + load-command dump ─────────────────────────────────────

// LogHeader dumps the Mach-O header fields and every load command at verbosity 3.
func (s *Slice) LogHeader(l *Logger) {
	if !l.Active(VerbosityV3) {
		return
	}
	h := &s.header
	bo := s.order()

	endian := "little-endian"
	if s.bigEndian {
		endian = "big-endian"
	}

	l.Section("Mach-O Header")
	l.V3("  magic:      0x%08x  (%s)", h.Magic, endian)
	l.V3("  cputype:    0x%08x  %s", h.CPU, cpuTypeName(h.CPU))
	l.V3("  cpusubtype: 0x%08x", h.SubCPU)
	l.V3("  filetype:   0x%08x  %s", h.FileType, fileTypeName(h.FileType))
	l.V3("  ncmds:      %d", h.NCmds)
	l.V3("  sizeofcmds: %d bytes", h.SizeOfCmds)
	l.V3("  flags:      0x%08x  %s", h.Flags, machoHeaderFlagsStr(h.Flags))

	l.Section("Load Commands")
	for i, lc := range s.loadCmds {
		name := lcName(lc.Cmd)
		b := s.Bytes[lc.Offset : lc.Offset+int64(lc.Size)]

		switch lc.Cmd {
		case lcSegment64:
			seg := parseSegment64(b, bo, lc.Offset)
			l.V3("  [%2d] %-34s  size=%-5d  %-12s  vmaddr=0x%016x  vmsize=0x%016x  fileoff=%-8d  filesize=%d",
				i, name, lc.Size, seg.Name,
				seg.VMAddr, seg.VMSize,
				seg.FileOff, seg.FileSize)
		case lcCodeSignature:
			if len(b) >= 16 {
				dataOff := bo.Uint32(b[8:])
				dataSize := bo.Uint32(b[12:])
				l.V3("  [%2d] %-34s  size=%-5d  dataoff=%-8d  datasize=%d",
					i, name, lc.Size, dataOff, dataSize)
			} else {
				l.V3("  [%2d] %-34s  size=%d", i, name, lc.Size)
			}
		default:
			l.V3("  [%2d] %-34s  size=%d", i, name, lc.Size)
		}
	}
}

// ── Name lookup tables ────────────────────────────────────────────────────────

func cpuTypeName(cpu uint32) string {
	switch cpu {
	case 0x0100000c:
		return "arm64"
	case 0x01000007:
		return "x86_64"
	case 0x0000000c:
		return "arm"
	case 0x00000007:
		return "x86"
	case 0x01000012:
		return "arm64_32"
	default:
		return fmt.Sprintf("cpu_0x%08x", cpu)
	}
}

func fileTypeName(ft uint32) string {
	switch ft {
	case 0x1:
		return "MH_OBJECT"
	case 0x2:
		return "MH_EXECUTE"
	case 0x5:
		return "MH_PRELOAD"
	case 0x6:
		return "MH_DYLIB"
	case 0x7:
		return "MH_DYLINKER"
	case 0x8:
		return "MH_BUNDLE"
	case 0x9:
		return "MH_DYLIB_STUB"
	case 0xa:
		return "MH_DSYM"
	case 0xb:
		return "MH_KEXT_BUNDLE"
	default:
		return fmt.Sprintf("MH_0x%x", ft)
	}
}

func machoHeaderFlagsStr(f uint32) string {
	type bit struct {
		v uint32
		s string
	}
	bits := []bit{
		{0x00000001, "NOUNDEFS"},
		{0x00000002, "INCRLINK"},
		{0x00000004, "DYLDLINK"},
		{0x00000008, "BINDATLOAD"},
		{0x00000010, "PREBOUND"},
		{0x00000020, "SPLIT_SEGS"},
		{0x00000080, "TWOLEVEL"},
		{0x00000100, "FORCE_FLAT"},
		{0x00001000, "SUBSECTIONS_VIA_SYMBOLS"},
		{0x00010000, "WEAK_DEFINES"},
		{0x00020000, "BINDS_TO_WEAK"},
		{0x00040000, "ALLOW_STACK_EXECUTION"},
		{0x00200000, "PIE"},
		{0x00400000, "DEAD_STRIPPABLE_DYLIB"},
		{0x00800000, "HAS_TLV_DESCRIPTORS"},
		{0x01000000, "NO_HEAP_EXECUTION"},
		{0x02000000, "APP_EXTENSION_SAFE"},
	}
	var parts []string
	for _, b := range bits {
		if f&b.v != 0 {
			parts = append(parts, b.s)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

func lcName(cmd uint32) string {
	switch cmd {
	case 0x00000001:
		return "LC_SEGMENT"
	case 0x00000002:
		return "LC_SYMTAB"
	case 0x00000004:
		return "LC_THREAD"
	case 0x00000005:
		return "LC_UNIXTHREAD"
	case 0x0000000b:
		return "LC_DYSYMTAB"
	case 0x0000000c:
		return "LC_LOAD_DYLIB"
	case 0x0000000e:
		return "LC_LOAD_DYLINKER"
	case 0x00000019:
		return "LC_SEGMENT_64"
	case 0x0000001b:
		return "LC_UUID"
	case 0x0000001d:
		return "LC_CODE_SIGNATURE"
	case 0x0000001e:
		return "LC_SEGMENT_SPLIT_INFO"
	case 0x00000021:
		return "LC_ENCRYPTION_INFO"
	case 0x00000026:
		return "LC_FUNCTION_STARTS"
	case 0x00000029:
		return "LC_DATA_IN_CODE"
	case 0x0000002a:
		return "LC_SOURCE_VERSION"
	case 0x0000002c:
		return "LC_ENCRYPTION_INFO_64"
	case 0x00000032:
		return "LC_BUILD_VERSION"
	case 0x8000001b:
		return "LC_RPATH"
	case 0x8000001f:
		return "LC_REEXPORT_DYLIB"
	case 0x80000022:
		return "LC_DYLD_INFO_ONLY"
	case 0x80000026:
		return "LC_DYLD_INFO"
	case 0x80000028:
		return "LC_MAIN"
	case 0x80000033:
		return "LC_DYLD_EXPORTS_TRIE"
	case 0x80000034:
		return "LC_DYLD_CHAINED_FIXUPS"
	default:
		return fmt.Sprintf("LC_0x%08x", cmd)
	}
}