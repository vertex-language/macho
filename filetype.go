package macho

// FileType is the filetype field of a Mach-O header.
type FileType uint32

const (
	MH_OBJECT      FileType = 0x1 // relocatable object
	MH_EXECUTE     FileType = 0x2 // demand-paged executable
	MH_FVMLIB      FileType = 0x3 // fixed VM shared library (obsolete)
	MH_CORE        FileType = 0x4
	MH_PRELOAD     FileType = 0x5
	MH_DYLIB       FileType = 0x6
	MH_DYLINKER    FileType = 0x7
	MH_BUNDLE      FileType = 0x8
	MH_DYLIB_STUB  FileType = 0x9 // static-link stub, no section contents
	MH_DSYM        FileType = 0xa // companion debug-info file
	MH_KEXT_BUNDLE FileType = 0xb
	MH_FILESET     FileType = 0xc
)

func (t FileType) String() string {
	switch t {
	case MH_OBJECT:
		return "MH_OBJECT"
	case MH_EXECUTE:
		return "MH_EXECUTE"
	case MH_FVMLIB:
		return "MH_FVMLIB"
	case MH_CORE:
		return "MH_CORE"
	case MH_PRELOAD:
		return "MH_PRELOAD"
	case MH_DYLIB:
		return "MH_DYLIB"
	case MH_DYLINKER:
		return "MH_DYLINKER"
	case MH_BUNDLE:
		return "MH_BUNDLE"
	case MH_DYLIB_STUB:
		return "MH_DYLIB_STUB"
	case MH_DSYM:
		return "MH_DSYM"
	case MH_KEXT_BUNDLE:
		return "MH_KEXT_BUNDLE"
	case MH_FILESET:
		return "MH_FILESET"
	}
	return "MH_?"
}

// Flags is the flags field of a Mach-O header.
type Flags uint32

const (
	MH_NOUNDEFS                      Flags = 0x1
	MH_INCRLINK                      Flags = 0x2
	MH_DYLDLINK                      Flags = 0x4
	MH_BINDATLOAD                    Flags = 0x8
	MH_PREBOUND                      Flags = 0x10
	MH_SPLIT_SEGS                    Flags = 0x20
	MH_LAZY_INIT                     Flags = 0x40 // obsolete
	MH_TWOLEVEL                      Flags = 0x80
	MH_FORCE_FLAT                    Flags = 0x100
	MH_NOMULTIDEFS                   Flags = 0x200
	MH_NOFIXPREBINDING               Flags = 0x400
	MH_PREBINDABLE                   Flags = 0x800
	MH_ALLMODSBOUND                  Flags = 0x1000
	MH_SUBSECTIONS_VIA_SYMBOLS       Flags = 0x2000
	MH_CANONICAL                     Flags = 0x4000
	MH_WEAK_DEFINES                  Flags = 0x8000
	MH_BINDS_TO_WEAK                 Flags = 0x10000
	MH_ALLOW_STACK_EXECUTION         Flags = 0x20000
	MH_ROOT_SAFE                     Flags = 0x40000
	MH_SETUID_SAFE                   Flags = 0x80000
	MH_NO_REEXPORTED_DYLIBS          Flags = 0x100000
	MH_PIE                           Flags = 0x200000
	MH_DEAD_STRIPPABLE_DYLIB         Flags = 0x400000
	MH_HAS_TLV_DESCRIPTORS           Flags = 0x800000
	MH_NO_HEAP_EXECUTION             Flags = 0x1000000
	MH_APP_EXTENSION_SAFE            Flags = 0x2000000
	MH_NLIST_OUTOFSYNC_WITH_DYLDINFO Flags = 0x4000000
	MH_SIM_SUPPORT                   Flags = 0x8000000
	MH_DYLIB_IN_CACHE                Flags = 0x80000000
)

// Has reports whether every bit in f is set in fl.
func (fl Flags) Has(f Flags) bool { return fl&f == f }