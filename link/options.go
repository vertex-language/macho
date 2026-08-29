// Package link is the link pipeline: resolution, layout, relocation, and
// emission of a finished Mach-O image.
//
// It is one flat package on purpose. The Mach-O metadata tables are too
// entangled with layout to sit behind an import boundary — __LINKEDIT's
// contents depend on the symbol table, which depends on dead-stripping, which
// depends on relocations, which depend on addresses, which depend on the size
// of the load commands, which depend on how many segments layout produced.
// Splitting that into dyld/, linkedit/, and unwind/ subpackages would mean
// either exporting most of it or threading it all through parameters.
//
// link never imports an architecture package. It discovers a backend through
// backend.For, and everything machine-specific goes through that interface.
package link

import (
	"fmt"

	"github.com/vertex-language/macho"
)

// OutputKind is the kind of file a link produces.
type OutputKind uint8

const (
	// OutputExecute is a main executable, MH_EXECUTE. It is the only kind
	// that gets a __PAGEZERO and the only one with an entry point.
	OutputExecute OutputKind = iota

	// OutputDylib is a shared library, MH_DYLIB. It needs an install name,
	// which is the path clients record and dyld uses to find it.
	OutputDylib

	// OutputBundle is a loadable bundle, MH_BUNDLE. It resolves undefined
	// symbols against its bundle loader as though the loader were a dylib.
	OutputBundle

	// OutputObject is `ld -r`: a merged MH_OBJECT rather than a linked image.
	// It is unimplemented; producing one requires regenerating relocations
	// for the merged output, which nothing here does.
	OutputObject
)

func (k OutputKind) String() string {
	switch k {
	case OutputExecute:
		return "executable"
	case OutputDylib:
		return "dylib"
	case OutputBundle:
		return "bundle"
	case OutputObject:
		return "object"
	}
	return "output(?)"
}

// FileType returns the Mach-O filetype for this output kind.
func (k OutputKind) FileType() macho.FileType {
	switch k {
	case OutputDylib:
		return macho.MH_DYLIB
	case OutputBundle:
		return macho.MH_BUNDLE
	case OutputObject:
		return macho.MH_OBJECT
	}
	return macho.MH_EXECUTE
}

// UndefinedTreatment is what to do about a symbol nothing defines.
type UndefinedTreatment uint8

const (
	// UndefinedFail fails the link. This is the default and very nearly
	// always what is wanted.
	UndefinedFail UndefinedTreatment = iota

	// UndefinedWarning reports and continues, leaving the symbol undefined in
	// the output.
	UndefinedWarning

	// UndefinedSuppress leaves the symbol undefined silently.
	UndefinedSuppress

	// UndefinedDynamicLookup marks every unresolved symbol for runtime lookup
	// across all loaded images.
	//
	// This defeats the two-level namespace for those symbols: with no library
	// recorded, dyld has to search every image and takes whichever definition
	// it finds first. That is slower and it is a correctness hazard — two
	// libraries exporting one name become indistinguishable. Apple deprecated
	// it for good reason, and it is here because real build systems still
	// pass it.
	UndefinedDynamicLookup
)

func (t UndefinedTreatment) String() string {
	switch t {
	case UndefinedWarning:
		return "warning"
	case UndefinedSuppress:
		return "suppress"
	case UndefinedDynamicLookup:
		return "dynamic_lookup"
	}
	return "error"
}

// Namespace is how a reference to a library symbol is recorded.
type Namespace uint8

const (
	// NamespaceTwoLevel records which library each undefined symbol came
	// from, in the high byte of n_desc. dyld then binds directly against that
	// library. This is the default and the only sane choice.
	NamespaceTwoLevel Namespace = iota

	// NamespaceFlat records nothing, and dyld searches every loaded image in
	// load order.
	//
	// Two consequences beyond the runtime cost, both of which this package
	// has to implement rather than merely tolerate. Indirect dylibs become
	// visible: under two-level the linker only looks at the libraries named
	// on the command line plus whatever they re-export, while under flat it
	// loads everything they transitively depend on and resolves against all
	// of it. And every undefine in every loaded dylib must itself resolve at
	// build time, which two-level does not check.
	//
	// It also costs diagnostic quality: with no ordinal recorded,
	// UndefinedError can no longer say which library a symbol was expected
	// from. That degradation matches ld64 and is intentional, but it is a
	// real loss.
	NamespaceFlat
)

func (n Namespace) String() string {
	if n == NamespaceFlat {
		return "flat"
	}
	return "two-level"
}

// CommonsTreatment is how a tentative definition interacts with dylibs.
type CommonsTreatment uint8

const (
	// CommonsIgnoreDylibs promotes a tentative definition to a real one
	// without consulting any dylib. This is the default, and it is worth
	// stating plainly because it is the opposite of what most people assume:
	// a common symbol in an object silently wins over an exported definition
	// of the same name in a linked library, with no diagnostic.
	CommonsIgnoreDylibs CommonsTreatment = iota

	// CommonsUseDylibs lets a dylib's definition replace a tentative one.
	CommonsUseDylibs

	// CommonsError reports the conflict instead of resolving it. This is what
	// a build that cares should use; the usual cause is a missing `extern` in
	// a header.
	CommonsError
)

// Options is the single configuration truth for a link.
//
// ld64 never had SECTIONS scripts and neither does this. Everything a linker
// script would express — segment addresses, protections, injected section
// content, symbol ordering — is a field here or a setter on Linker.
type Options struct {
	// Output decides the filetype and, through it, whether there is a
	// __PAGEZERO, an entry point, and an install name.
	Output OutputKind

	// Entry is the entry point symbol for an executable.
	//
	// The default is "_main", not ld64's historical "start". Those differ
	// because they belong to different mechanisms: LC_UNIXTHREAD started at
	// crt1.o's `start`, while LC_MAIN — which is what this tree emits — names
	// the C `main` directly and lets libSystem set up argc and argv. Emitting
	// LC_MAIN pointing at `start` would run the C runtime's setup twice.
	Entry string

	// InstallName is LC_ID_DYLIB, required for a dylib. Clients record it as
	// the path dyld should use to find this library.
	InstallName string

	// CurrentVersion and CompatVersion are the dylib version numbers. dyld
	// refuses to load a library whose compatibility version is older than the
	// one a client recorded.
	CurrentVersion macho.Version
	CompatVersion  macho.Version

	// BundleLoader is the executable a bundle will be loaded into.
	// Undefined symbols in the bundle resolve against it as though it were a
	// dylib, and bind with EXECUTABLE_ORDINAL rather than a library ordinal.
	BundleLoader string

	Undefined UndefinedTreatment
	Namespace Namespace
	Commons   CommonsTreatment

	// DeadStrip enables the sweep. Roots are the entry point, exported
	// symbols, initializers and terminators, and anything marked
	// S_ATTR_NO_DEAD_STRIP, S_ATTR_LIVE_SUPPORT, or N_NO_DEAD_STRIP.
	DeadStrip bool

	// DeadStripDylibs suppresses LC_LOAD_DYLIB for libraries that supplied no
	// symbols. It is unsafe for a library that is needed for a side effect —
	// an initializer, say — since nothing in the symbol graph records that.
	DeadStripDylibs bool

	// KeepPrivateExterns leaves private externs as private externs instead of
	// demoting them to locals.
	KeepPrivateExterns bool

	// AllLoad loads every member of every archive; LoadAllObjC loads every
	// member that defines an Objective-C class or category.
	//
	// The ObjC rule exists because Objective-C categories have no symbol that
	// anything references: a category adds methods to a class at load time
	// through a table in __DATA, and nothing in the program names it. Ordinary
	// archive semantics therefore drop it, and the methods silently do not
	// exist at runtime.
	AllLoad     bool
	LoadAllObjC bool

	// ForceLoad names archives every member of which is loaded regardless of
	// whether anything references it.
	ForceLoad []string

	// Undefineds are -u: symbols that must be defined for the link to
	// succeed. Naming one forces its archive member to be extracted, which is
	// what the option is really for.
	Undefineds []string

	// AllowUndefined are -U: individual symbols permitted to go unresolved,
	// which bind with DYNAMIC_LOOKUP_ORDINAL.
	AllowUndefined []string

	// ExportedSymbols, when non-nil, is the exhaustive list of names that
	// stay global. Everything else is demoted to a private extern.
	// UnexportedSymbols is the inverse.
	ExportedSymbols   []string
	UnexportedSymbols []string

	// OrderFile is -order_file: symbols moved to the front of their section,
	// in the order listed.
	OrderFile []string

	// PageZeroSize overrides the size of __PAGEZERO. Zero means the default
	// for the target's width — 4 GiB for 64-bit — and an explicit zero is
	// spelled by NoPageZero.
	//
	// 4 GiB rather than one page is what makes a null pointer plus a large
	// 32-bit offset still fault instead of landing in mapped memory.
	PageZeroSize uint64
	NoPageZero   bool

	// PageSize overrides segment alignment. Zero means the target's natural
	// page size: 16 KiB on arm64, 4 KiB on x86_64.
	PageSize uint64

	// SegmentAddress pins a segment's vmaddr.
	//
	// Unlike its ELF counterpart this genuinely pins the segment: a Mach-O
	// segment carries an explicit vmaddr, so there is nothing to infer and
	// nothing to approximate.
	SegmentAddress map[string]uint64

	// SegmentProt overrides a segment's maxprot and initprot.
	SegmentProt map[string]ProtPair

	// SectionData is -sectcreate: raw bytes injected as a section. The
	// (segment, section) pair must not collide with a section from any input.
	SectionData map[macho.SecName][]byte

	// RPaths are LC_RPATH entries, the search path for load paths beginning
	// with @rpath/.
	RPaths []string

	// Flags are extra header flags OR-ed into the computed set.
	Flags macho.Flags

	// MaxLayoutRounds bounds the stub, thunk, and relaxation fixpoint.
	// Zero means DefaultMaxLayoutRounds.
	MaxLayoutRounds int
}

// ProtPair is a segment's maxprot and initprot.
type ProtPair struct{ Max, Init macho.Prot }

// DefaultMaxLayoutRounds bounds the layout fixpoint.
//
// The loop converges monotonically — stubs and thunks only ever grow, and
// relaxation only ever shrinks instructions without moving anything that has
// already been placed past it — so in practice it settles in two or three
// rounds. The bound exists so that a backend with a bug that oscillates fails
// with ErrLayoutDivergence rather than hanging.
const DefaultMaxLayoutRounds = 20

// defaults fills in the zero values that have a meaningful default.
func (o *Options) defaults() {
	if o.Entry == "" {
		o.Entry = "_main"
	}
	if o.MaxLayoutRounds == 0 {
		o.MaxLayoutRounds = DefaultMaxLayoutRounds
	}
	if o.CompatVersion == 0 {
		o.CompatVersion = macho.MakeVersion(1, 0, 0)
	}
	if o.CurrentVersion == 0 {
		o.CurrentVersion = macho.MakeVersion(1, 0, 0)
	}
}

// Validate reports a configuration that cannot produce a file.
func (o *Options) Validate() error {
	switch o.Output {
	case OutputDylib:
		if o.InstallName == "" {
			return fmt.Errorf("link: a dylib needs an install name; clients record it as the path dyld resolves against")
		}
	case OutputBundle, OutputExecute:
		if o.InstallName != "" {
			return fmt.Errorf("link: an install name is meaningful only for a dylib, not for a %v", o.Output)
		}
	case OutputObject:
		return fmt.Errorf("link: %w: -r output regenerates relocations, which is unimplemented",
			ErrUnimplemented)
	}
	if o.Output != OutputBundle && o.BundleLoader != "" {
		return fmt.Errorf("link: a bundle loader is meaningful only for a bundle, not for a %v", o.Output)
	}
	if o.NoPageZero && o.PageZeroSize != 0 {
		return fmt.Errorf("link: NoPageZero and a nonzero PageZeroSize contradict each other")
	}
	if o.PageSize != 0 && o.PageSize&(o.PageSize-1) != 0 {
		return fmt.Errorf("link: page size %d is not a power of two", o.PageSize)
	}
	if len(o.ExportedSymbols) > 0 && len(o.UnexportedSymbols) > 0 {
		return fmt.Errorf("link: an exported-symbols list and an unexported-symbols list cannot both be given")
	}
	if o.MaxLayoutRounds < 1 {
		return fmt.Errorf("link: MaxLayoutRounds must be at least 1")
	}
	return nil
}

// hasPageZero reports whether this output gets a __PAGEZERO. Only a main
// executable does: a dylib or bundle is loaded into a process that already has
// one, and a second unmapped region at address zero would either fail to map
// or shadow the host's.
func (o *Options) hasPageZero() bool {
	return o.Output == OutputExecute && !o.NoPageZero
}