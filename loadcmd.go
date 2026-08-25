package macho

// LoadCmd is the cmd field of a load command.
type LoadCmd uint32

// LC_REQ_DYLD marks a load command that dyld must understand for the image to
// run. dyld refuses an image carrying an unknown command with this bit set,
// and ignores an unknown command without it.
const LC_REQ_DYLD LoadCmd = 0x80000000

const (
	LC_SEGMENT              LoadCmd = 0x1
	LC_SYMTAB               LoadCmd = 0x2
	LC_SYMSEG               LoadCmd = 0x3 // obsolete
	LC_THREAD               LoadCmd = 0x4
	LC_UNIXTHREAD           LoadCmd = 0x5
	LC_LOADFVMLIB           LoadCmd = 0x6
	LC_IDFVMLIB             LoadCmd = 0x7
	LC_IDENT                LoadCmd = 0x8 // obsolete
	LC_FVMFILE              LoadCmd = 0x9
	LC_PREPAGE              LoadCmd = 0xa
	LC_DYSYMTAB             LoadCmd = 0xb
	LC_LOAD_DYLIB           LoadCmd = 0xc
	LC_ID_DYLIB             LoadCmd = 0xd
	LC_LOAD_DYLINKER        LoadCmd = 0xe
	LC_ID_DYLINKER          LoadCmd = 0xf
	LC_PREBOUND_DYLIB       LoadCmd = 0x10
	LC_ROUTINES             LoadCmd = 0x11
	LC_SUB_FRAMEWORK        LoadCmd = 0x12
	LC_SUB_UMBRELLA         LoadCmd = 0x13
	LC_SUB_CLIENT           LoadCmd = 0x14
	LC_SUB_LIBRARY          LoadCmd = 0x15
	LC_TWOLEVEL_HINTS       LoadCmd = 0x16
	LC_PREBIND_CKSUM        LoadCmd = 0x17
	LC_LOAD_WEAK_DYLIB      LoadCmd = 0x18 | LC_REQ_DYLD
	LC_SEGMENT_64           LoadCmd = 0x19
	LC_ROUTINES_64          LoadCmd = 0x1a
	LC_UUID                 LoadCmd = 0x1b
	LC_RPATH                LoadCmd = 0x1c | LC_REQ_DYLD
	LC_CODE_SIGNATURE       LoadCmd = 0x1d
	LC_SEGMENT_SPLIT_INFO   LoadCmd = 0x1e
	LC_REEXPORT_DYLIB       LoadCmd = 0x1f | LC_REQ_DYLD
	LC_LAZY_LOAD_DYLIB      LoadCmd = 0x20
	LC_ENCRYPTION_INFO      LoadCmd = 0x21
	LC_DYLD_INFO            LoadCmd = 0x22
	LC_DYLD_INFO_ONLY       LoadCmd = 0x22 | LC_REQ_DYLD
	LC_LOAD_UPWARD_DYLIB    LoadCmd = 0x23 | LC_REQ_DYLD
	LC_VERSION_MIN_MACOSX   LoadCmd = 0x24
	LC_VERSION_MIN_IPHONEOS LoadCmd = 0x25
	LC_FUNCTION_STARTS      LoadCmd = 0x26
	LC_DYLD_ENVIRONMENT     LoadCmd = 0x27
	LC_MAIN                 LoadCmd = 0x28 | LC_REQ_DYLD
	LC_DATA_IN_CODE         LoadCmd = 0x29
	LC_SOURCE_VERSION       LoadCmd = 0x2a
	LC_DYLIB_CODE_SIGN_DRS  LoadCmd = 0x2b
	LC_ENCRYPTION_INFO_64   LoadCmd = 0x2c
	LC_LINKER_OPTION        LoadCmd = 0x2d
	LC_LINKER_OPTIMIZATION_HINT LoadCmd = 0x2e
	LC_VERSION_MIN_TVOS     LoadCmd = 0x2f
	LC_VERSION_MIN_WATCHOS  LoadCmd = 0x30
	LC_NOTE                 LoadCmd = 0x31
	LC_BUILD_VERSION        LoadCmd = 0x32
	LC_DYLD_EXPORTS_TRIE    LoadCmd = 0x33 | LC_REQ_DYLD
	LC_DYLD_CHAINED_FIXUPS  LoadCmd = 0x34 | LC_REQ_DYLD
	LC_FILESET_ENTRY        LoadCmd = 0x35 | LC_REQ_DYLD
)

// Required reports whether the LC_REQ_DYLD bit is set.
func (c LoadCmd) Required() bool { return c&LC_REQ_DYLD != 0 }

// Base returns c with LC_REQ_DYLD cleared.
func (c LoadCmd) Base() LoadCmd { return c &^ LC_REQ_DYLD }

// SegmentCmd returns the segment load command for a given width.
func SegmentCmd(w Width) LoadCmd {
	if w.Wide() {
		return LC_SEGMENT_64
	}
	return LC_SEGMENT
}

func (c LoadCmd) String() string {
	if s, ok := loadCmdNames[c]; ok {
		return s
	}
	return "LC_?"
}

var loadCmdNames = map[LoadCmd]string{
	LC_SEGMENT: "LC_SEGMENT", LC_SYMTAB: "LC_SYMTAB", LC_SYMSEG: "LC_SYMSEG",
	LC_THREAD: "LC_THREAD", LC_UNIXTHREAD: "LC_UNIXTHREAD",
	LC_LOADFVMLIB: "LC_LOADFVMLIB", LC_IDFVMLIB: "LC_IDFVMLIB",
	LC_IDENT: "LC_IDENT", LC_FVMFILE: "LC_FVMFILE", LC_PREPAGE: "LC_PREPAGE",
	LC_DYSYMTAB: "LC_DYSYMTAB", LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
	LC_ID_DYLIB: "LC_ID_DYLIB", LC_LOAD_DYLINKER: "LC_LOAD_DYLINKER",
	LC_ID_DYLINKER: "LC_ID_DYLINKER", LC_PREBOUND_DYLIB: "LC_PREBOUND_DYLIB",
	LC_ROUTINES: "LC_ROUTINES", LC_SUB_FRAMEWORK: "LC_SUB_FRAMEWORK",
	LC_SUB_UMBRELLA: "LC_SUB_UMBRELLA", LC_SUB_CLIENT: "LC_SUB_CLIENT",
	LC_SUB_LIBRARY: "LC_SUB_LIBRARY", LC_TWOLEVEL_HINTS: "LC_TWOLEVEL_HINTS",
	LC_PREBIND_CKSUM: "LC_PREBIND_CKSUM", LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
	LC_SEGMENT_64: "LC_SEGMENT_64", LC_ROUTINES_64: "LC_ROUTINES_64",
	LC_UUID: "LC_UUID", LC_RPATH: "LC_RPATH",
	LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE", LC_SEGMENT_SPLIT_INFO: "LC_SEGMENT_SPLIT_INFO",
	LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB", LC_LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB",
	LC_ENCRYPTION_INFO: "LC_ENCRYPTION_INFO", LC_DYLD_INFO: "LC_DYLD_INFO",
	LC_DYLD_INFO_ONLY: "LC_DYLD_INFO_ONLY", LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
	LC_VERSION_MIN_MACOSX: "LC_VERSION_MIN_MACOSX",
	LC_VERSION_MIN_IPHONEOS: "LC_VERSION_MIN_IPHONEOS",
	LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS", LC_DYLD_ENVIRONMENT: "LC_DYLD_ENVIRONMENT",
	LC_MAIN: "LC_MAIN", LC_DATA_IN_CODE: "LC_DATA_IN_CODE",
	LC_SOURCE_VERSION: "LC_SOURCE_VERSION", LC_DYLIB_CODE_SIGN_DRS: "LC_DYLIB_CODE_SIGN_DRS",
	LC_ENCRYPTION_INFO_64: "LC_ENCRYPTION_INFO_64", LC_LINKER_OPTION: "LC_LINKER_OPTION",
	LC_LINKER_OPTIMIZATION_HINT: "LC_LINKER_OPTIMIZATION_HINT",
	LC_VERSION_MIN_TVOS: "LC_VERSION_MIN_TVOS", LC_VERSION_MIN_WATCHOS: "LC_VERSION_MIN_WATCHOS",
	LC_NOTE: "LC_NOTE", LC_BUILD_VERSION: "LC_BUILD_VERSION",
	LC_DYLD_EXPORTS_TRIE: "LC_DYLD_EXPORTS_TRIE",
	LC_DYLD_CHAINED_FIXUPS: "LC_DYLD_CHAINED_FIXUPS", LC_FILESET_ENTRY: "LC_FILESET_ENTRY",
}