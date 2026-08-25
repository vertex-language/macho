// Package backend is the seam between the linker and the machine.
//
// Everything that depends on a processor's instruction encodings, its stub and
// GOT shapes, its branch reach, or its pointer-authentication rules lives
// behind the Backend interface. link never imports arm64, x86_64, or any other
// architecture package; it calls For and gets one.
//
// The split is not cosmetic. A linker that reaches for an architecture package
// directly ends up with a `switch cpu` in the middle of the layout fixpoint,
// and every new architecture edits every such switch. Here a new architecture
// is one package implementing one interface plus a blank import.
//
// # What is and is not a backend concern
//
// A backend answers questions the psABI decides: what does this r_type mean,
// how many bytes is a stub, how far can a branch reach, what goes in an
// instruction's immediate field. It does not decide layout, ordering, symbol
// resolution, or anything about __LINKEDIT — those are the same for every
// architecture and belong to link.
//
// The dividing line is sharpest around relocations. link knows a relocation
// exists, which symbol it names, and what address that symbol landed at.
// Only the backend knows how to write the value into the four bytes at
// r_address, because only the backend knows the instruction encoding.
//
// # Registration
//
// A backend registers itself from an init function, so importing the package
// for effect is what makes it available:
//
//	import _ "github.com/vertex-language/macho/arm64"
//
// Register panics on a duplicate (cputype, cpusubtype) pair. That is a
// documented API-misuse case — two packages claiming one architecture is a
// build-configuration bug, not an input error — and panicking at init is
// strictly better than resolving it arbitrarily at link time.
//
// # Deviation from the README's interface sketch
//
// The README sketches Backend with a CPU method and no SubCPU. That cannot
// work: arm64 and arm64e are one cputype distinguished only by cpusubtype, and
// they are two backends with genuinely different behaviour — arm64e signs
// pointers and arm64 does not. SubCPU is therefore part of the interface and
// part of the registry key. The README's Errors table already assumes this,
// since ErrNoBackend is documented as covering the target's CPU/SubCPU.
//
// # Known gap
//
// Nothing here names a chained-fixup pointer format. Choosing between
// DYLD_CHAINED_PTR_64_OFFSET and DYLD_CHAINED_PTR_ARM64E_USERLAND24 is a psABI
// decision and belongs behind this interface, but macho/fixups.go is constants
// only and nothing encodes a chain yet. When it does, the choice becomes an
// optional interface here rather than a switch in link/fixups.go.
package backend

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/image"
)

var (
	// ErrNoBackend means no backend is registered for a target's cputype and
	// cpusubtype. The usual cause is a missing blank import of the
	// architecture package.
	ErrNoBackend = errors.New("backend: no backend registered for the target")

	// ErrUnsupportedReloc means a backend was handed an r_type it does not
	// implement. It is an error rather than a skipped entry: a relocation that
	// is not applied leaves whatever the compiler put in the instruction
	// stream, which is a plausible-looking wrong address.
	ErrUnsupportedReloc = errors.New("backend: unsupported relocation type")
)

// Backend is everything link needs to know about one architecture.
//
// A Backend is stateless with respect to a link. It is registered once at init
// and may serve several links, possibly concurrently, so an implementation
// must not keep per-link state in itself — that is what Reqs and Image are
// for.
type Backend interface {
	// CPU and SubCPU identify the architecture this backend serves. SubCPU is
	// compared with Base(), so the capability byte plays no part.
	CPU() macho.CPU
	SubCPU() macho.SubCPU

	// Classify maps an architecture-specific r_type to the Kind that says
	// what the linker must arrange for it. An unrecognized type is
	// KindUnknown, which link turns into ErrUnsupportedReloc.
	Classify(typ uint8) Kind

	// Scan walks the image's live atoms and records what the link will have to
	// synthesize: GOT slots, stubs, TLV descriptors, and the rebase and bind
	// sites the fixup encoder will need. It runs once, in the open phase,
	// before any address exists — so it may read relocations and symbols and
	// must not read an address.
	Scan(img *image.Image, reqs *Reqs) error

	// Apply writes one relocation into the output buffer. It runs after
	// Freeze, when every address is final.
	Apply(s *Site, r image.Reloc) error

	// Addend recovers the addend for a relocation from the instruction stream.
	//
	// Mach-O relocations carry no r_addend field: the value lives in the bytes
	// the relocation applies to, encoded in whatever instruction field is
	// there, or on arm64 travels in a preceding ARM64_RELOC_ADDEND entry that
	// link has already folded in. Decoding an instruction's immediate is a
	// psABI property, which is why this is here and not in obj.
	//
	// The bool reports whether an addend could be recovered at all; false is
	// not an error, it means this relocation kind carries none.
	Addend(content []byte, off uint64, r image.Reloc) (int64, bool)

	// WordSize is the pointer size in bytes: 8 for arm64 and x86_64, 4 for
	// arm64_32. It is a function of the CPU and must agree with
	// CPU.Width().Bits()/8; Register checks that it does.
	WordSize() int
}

// Stubber is the optional interface a backend implements to describe and
// generate stubs and GOT entries.
//
// It is optional because a backend can be useful without it — enough to read
// and relocate objects for an `ld -r` style partial link — but no backend can
// produce a dynamic executable without one.
//
// The write methods take addresses rather than symbols because they run after
// Freeze, when link has already resolved everything and only the byte
// encoding is left.
type Stubber interface {
	// GotShape and StubShape describe the sections and sizes link must reserve
	// during layout. They are pure functions of the architecture and are
	// called before any address is assigned.
	GotShape() GotShape
	StubShape() StubShape

	// WriteGotSlot writes one pointer-sized GOT entry.
	WriteGotSlot(dst []byte, target uint64) error

	// WriteStub writes one entry of __stubs. pointerAddr is the address of the
	// slot the stub loads through: the __got entry for a non-lazy stub, the
	// __la_symbol_ptr entry for a lazy one.
	WriteStub(dst []byte, stubAddr, pointerAddr uint64) error

	// WriteStubHelperHeader writes the one-per-image prologue of
	// __stub_helper, which pushes the image's dyld_private cookie and jumps
	// through the GOT to dyld_stub_binder.
	//
	// Lazy binding only. A backend whose StubShape is StubNonLazy may return
	// an error here; link will not call it.
	WriteStubHelperHeader(dst []byte, headerAddr, dyldPrivateAddr, binderGotAddr uint64) error

	// WriteStubHelperEntry writes one per-symbol __stub_helper entry. lazyBindOff
	// is the byte offset of this symbol's opcodes within the lazy bind stream,
	// which is the argument the entry hands to dyld_stub_binder.
	WriteStubHelperEntry(dst []byte, entryAddr, headerAddr uint64, lazyBindOff uint32) error
}

// Thunker is the optional interface a backend implements when its branches
// cannot reach across a whole image.
//
// On arm64 this is not optional in practice. A BRANCH26 reaches about
// ±128 MiB, so any image larger than that needs range-extension thunks, and
// the thunk-growth fixpoint in Link is load-bearing rather than an
// optimization. x86_64 branches reach ±2 GiB and no x86_64 backend needs to
// implement this.
type Thunker interface {
	ThunkShape() ThunkShape

	// WriteThunk writes one thunk: a sequence that materializes target and
	// branches to it with no range limit.
	WriteThunk(dst []byte, thunkAddr, target uint64) error
}

// Relaxer is the optional interface a backend implements to rewrite
// instruction sequences that layout has made redundant.
//
// On arm64 this is LC_LINKER_OPTIMIZATION_HINT processing: an adrp+add pair
// whose target turned out to be within ±1 MiB collapses to adr+nop, and an
// adrp+ldr collapses to a pc-relative literal load. Both are pure size and
// launch-time wins and neither changes the program's meaning.
//
// Relax reports whether it changed anything, because a rewrite can shorten a
// sequence and therefore move everything after it — which is why it runs
// inside the layout fixpoint rather than after it.
type Relaxer interface {
	Relax(img *image.Image, reqs *Reqs) (changed bool, err error)
}

// Signer is the optional interface an arm64e backend implements to describe
// pointer authentication.
//
// It reports the signing schema a relocation asks for; producing the
// authenticated pointer on disk is the fixup encoder's job, since the schema
// travels in the chained-fixup entry rather than in the pointer's bytes.
type Signer interface {
	// PtrAuth returns the signing schema for an authenticated pointer
	// relocation, and false if the relocation is not one.
	PtrAuth(r image.Reloc) (PtrAuth, bool)
}

// AsStubber, AsThunker, AsRelaxer, and AsSigner are the discovery helpers link
// uses. They exist so link never writes a type assertion against an interface
// this package owns, which keeps the optional-interface set in one place.
func AsStubber(b Backend) (Stubber, bool) { s, ok := b.(Stubber); return s, ok }
func AsThunker(b Backend) (Thunker, bool) { t, ok := b.(Thunker); return t, ok }
func AsRelaxer(b Backend) (Relaxer, bool) { r, ok := b.(Relaxer); return r, ok }
func AsSigner(b Backend) (Signer, bool)   { s, ok := b.(Signer); return s, ok }

// regKey is a registry entry's identity: a cputype and a capability-stripped
// cpusubtype.
type regKey struct {
	cpu macho.CPU
	sub macho.SubCPU
}

var (
	mu       sync.RWMutex
	registry = make(map[regKey]Backend)

	// order is registration order. Lookups that may match more than one entry
	// walk this rather than the map, because map iteration order is random and
	// a linker that picks a different backend on different runs is not a thing
	// anyone can debug.
	order []Backend
)

// Register adds a backend to the registry.
//
// It panics on a duplicate architecture, on a nil backend, and on a WordSize
// that disagrees with the CPU's width. All three are build-configuration
// mistakes that would otherwise surface as a wrong file much later: a
// duplicate means two packages claim one architecture, and a WordSize that
// disagrees with CPU_ARCH_ABI64 would size every GOT slot wrongly.
func Register(b Backend) {
	if b == nil {
		panic("backend: Register(nil)")
	}
	cpu, sub := b.CPU(), b.SubCPU().Base()
	if w := cpu.Width(); w.Bits()/8 != b.WordSize() {
		panic(fmt.Sprintf("backend: %T reports WordSize %d for %v, whose width is %v",
			b, b.WordSize(), cpu, w))
	}

	mu.Lock()
	defer mu.Unlock()
	k := regKey{cpu, sub}
	if prev, dup := registry[k]; dup {
		panic(fmt.Sprintf("backend: %s registered twice, by %T and %T",
			macho.ArchName(cpu, sub), prev, b))
	}
	registry[k] = b
	order = append(order, b)
}

// For returns the backend for a target.
func For(t macho.Target) (Backend, error) {
	if !t.CPU.Supported() {
		return nil, fmt.Errorf("%w: %v", macho.ErrUnsupportedCPU, t.CPU)
	}
	return Find(t.CPU, t.SubCPU)
}

// Find returns the backend for a cputype and cpusubtype.
//
// Matching is exact on the cputype and on the capability-stripped cpusubtype,
// with one narrow exception: two subtypes that both mean "any implementation
// of this cputype" are interchangeable, because ParseArch("arm64_32") produces
// the V8 subtype while a backend may reasonably register ALL.
//
// There is deliberately no fallback from a specific subtype to a generic one.
// This is the opposite of fat slice selection, which does serve an arm64e
// request from an arm64 slice — and the difference is the point. A slice is a
// whole image and a compatible one still runs; a backend decides how
// relocations are written and whether pointers are signed, and handing an
// arm64e link the arm64 backend produces an image that dyld will refuse.
func Find(cpu macho.CPU, sub macho.SubCPU) (Backend, error) {
	want := sub.Base()

	mu.RLock()
	defer mu.RUnlock()

	if b, ok := registry[regKey{cpu, want}]; ok {
		return b, nil
	}
	if generic(cpu, want) {
		for _, b := range order {
			if b.CPU() == cpu && generic(cpu, b.SubCPU().Base()) {
				return b, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: %s; registered: %s",
		ErrNoBackend, macho.ArchName(cpu, sub), namesLocked())
}

// generic reports whether a subtype means "any implementation of this
// cputype" rather than naming a particular one. It mirrors fat/select.go's
// function of the same name, deliberately: the two answer the same question
// and drifting apart would make a slice and its backend disagree.
func generic(cpu macho.CPU, sub macho.SubCPU) bool {
	switch cpu {
	case macho.CPU_TYPE_ARM64:
		return sub == macho.CPU_SUBTYPE_ARM64_ALL || sub == macho.CPU_SUBTYPE_ARM64_V8
	case macho.CPU_TYPE_ARM64_32:
		return sub == macho.CPU_SUBTYPE_ARM64_32_ALL || sub == macho.CPU_SUBTYPE_ARM64_32_V8
	case macho.CPU_TYPE_X86_64:
		return sub == macho.CPU_SUBTYPE_X86_64_ALL
	}
	return false
}

// Registered returns every registered backend in registration order. It is for
// diagnostics and for a test that wants to assert the expected set is linked
// in.
func Registered() []Backend {
	mu.RLock()
	defer mu.RUnlock()
	return append([]Backend(nil), order...)
}

// Names returns the arch name of every registered backend, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	return sortedNamesLocked()
}

func sortedNamesLocked() []string {
	out := make([]string, 0, len(order))
	for _, b := range order {
		out = append(out, macho.ArchName(b.CPU(), b.SubCPU()))
	}
	sort.Strings(out)
	return out
}

func namesLocked() string {
	ns := sortedNamesLocked()
	if len(ns) == 0 {
		return "[none — is an architecture package imported?]"
	}
	s := ""
	for i, n := range ns {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return "[" + s + "]"
}