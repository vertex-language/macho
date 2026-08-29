package link

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/ar"
	"github.com/vertex-language/macho/fat"
	"github.com/vertex-language/macho/image"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/obj"
	"github.com/vertex-language/macho/tbd"
)

// inputKind is what an input contributes.
type inputKind uint8

const (
	inputObject  inputKind = iota // atoms and definitions
	inputArchive                  // definitions, on demand
	inputDylib                    // definitions that stay in the library
	inputStub                     // the same, described by a .tbd
)

// inputFile is one file on the link line.
type inputFile struct {
	name string
	kind inputKind

	obj *obj.File
	ar  *ar.File
	lib Library

	// split is the per-input bookkeeping split.go produces: each section's
	// atoms and each defining symbol's atom. It is nil until this input has
	// gone through splitInput, and stays nil for anything that is not an
	// object.
	split *splitState

	// forced marks an archive every member of which is loaded regardless of
	// whether anything references it: -force_load, -all_load, or the ObjC
	// rule.
	forced bool

	// ordinal is the two-level namespace library ordinal, assigned during
	// resolution for dylib and stub inputs only.
	ordinal macho.LibOrdinal

	// used records whether this library supplied any symbol, which is what
	// -dead_strip_dylibs acts on.
	used bool

	// imgInput is this input's image.Input, created on first use so that an
	// input contributing nothing never appears in the output.
	imgInput *image.Input

	closer interface{ Close() error }
}

func (f *inputFile) String() string { return f.name }

// Library is the resolution-time view of an input that supplies definitions
// without contributing atoms.
//
// A dylib and a .tbd stub are the same thing at this layer — a list of names
// this library exports, plus the libraries it re-exports — so both go through
// one interface and resolution never learns which it has. The stub adapter is
// below; the dylib adapter lands with read.go.
type Library interface {
	// InstallName is LC_ID_DYLIB: the path clients record and dyld resolves.
	// It is the library's identity, not the path it was read from, which is
	// why an SDK stub at /SDK/usr/lib/libSystem.tbd still names
	// /usr/lib/libSystem.B.dylib.
	InstallName() string

	CurrentVersion() macho.Version
	CompatVersion() macho.Version

	// Exports returns the symbols this library provides for the target.
	Exports(t macho.Target) []Export

	// Reexports returns the install names this library re-exports.
	//
	// Following them is not optional: libSystem defines almost nothing itself
	// and re-exports a dozen libraries under /usr/lib/system, so a resolver
	// that stops at the top level finds none of libc.
	Reexports(t macho.Target) []string

	// Clients returns the allowable clients, or nil if anything may link
	// against this library.
	Clients(t macho.Target) []string
}

// Export is one name a library provides.
type Export struct {
	Name        string
	Weak        bool
	ThreadLocal bool
}

// AddObject adds an object file already in memory.
//
// This is the path a caller uses to feed the object writer's output straight
// into a link with no file round-trip.
func (l *Linker) AddObject(name string, data []byte) error {
	f, err := obj.NewFile(binio.ExtentOf(data))
	if err != nil {
		return fmt.Errorf("link: %s: %w", name, err)
	}
	return l.addObject(name, f, nil)
}

// AddArchive adds a static archive already in memory.
func (l *Linker) AddArchive(name string, data []byte) error {
	a, err := ar.NewFile(binio.ExtentOf(data))
	if err != nil {
		return fmt.Errorf("link: %s: %w", name, err)
	}
	return l.addArchive(name, a, nil)
}

// AddStub adds a .tbd stub library.
func (l *Linker) AddStub(name string, data []byte) error {
	s, err := tbd.Parse(data)
	if err != nil {
		return fmt.Errorf("link: %s: %w", name, err)
	}
	lib := &stubLibrary{s: s}
	lib.resolveReexports(l.target, l.sdk)
	return l.addLibrary(name, inputStub, lib, nil)
}

// AddDylib adds a dylib as a link input.
//
// Reading a real Mach-O dylib for its exports needs read.go, which is not
// written. Everything a link actually needs from a system library is in its
// .tbd, so AddStub is the path that works today.
func (l *Linker) AddDylib(name string, data []byte) error {
	return fmt.Errorf("link: %s: %w: reading a dylib's exports needs read.go; use AddStub",
		name, ErrUnimplemented)
}

// OpenFile adds an input from disk, deciding what it is by looking at it.
//
// The extension is not consulted. A .a may be a universal archive, a .dylib
// may be a .tbd in disguise, and a file with no extension at all is perfectly
// legal — so the magic decides, as it does everywhere else in this tree.
func (l *Linker) OpenFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("link: %w", err)
	}
	return l.AddFile(path, data)
}

// AddFile adds an input whose kind is determined from its contents.
func (l *Linker) AddFile(name string, data []byte) error {
	switch {
	case ar.IsArchive(data):
		return l.AddArchive(name, data)

	case macho.IsFat(data):
		// A universal input contributes exactly one slice: the one matching
		// the target. Selection is graded rather than positional, so which
		// slice runs does not depend on the order they appear in the file.
		ff, err := fat.NewFile(binio.ExtentOf(data))
		if err != nil {
			return fmt.Errorf("link: %s: %w", name, err)
		}
		ext, err := ff.ExtentFor(l.target)
		if err != nil {
			return fmt.Errorf("link: %s: %w", name, err)
		}
		slice, err := ext.Bytes()
		if err != nil {
			return fmt.Errorf("link: %s: %w", name, err)
		}
		return l.AddFile(name, slice)

	case macho.Is(data):
		kind, err := macho.KindOf(data)
		if err != nil {
			return fmt.Errorf("link: %s: %w", name, err)
		}
		switch kind {
		case macho.KindObject:
			return l.AddObject(name, data)
		case macho.KindDylib, macho.KindDylibStub:
			return l.AddDylib(name, data)
		}
		return fmt.Errorf("link: %s is a %v and is not a link input", name, kind)
	}

	// A .tbd is YAML and has no magic, so it is what is left over rather than
	// something positively identified. Parse failures therefore report the
	// tbd error, which names the version, rather than a generic
	// "unrecognized file".
	return l.AddStub(name, data)
}

// addObject records an object input after checking it belongs in this link.
func (l *Linker) addObject(name string, f *obj.File, closer interface{ Close() error }) error {
	if err := l.checkTarget(name, f.Target()); err != nil {
		return err
	}
	l.inputs = append(l.inputs, &inputFile{
		name: name, kind: inputObject, obj: f, closer: closer,
	})
	return nil
}

func (l *Linker) addArchive(name string, a *ar.File, closer interface{ Close() error }) error {
	in := &inputFile{name: name, kind: inputArchive, ar: a, closer: closer}
	in.forced = l.opts.AllLoad
	for _, p := range l.opts.ForceLoad {
		if p == name {
			in.forced = true
		}
	}
	l.inputs = append(l.inputs, in)
	return nil
}

func (l *Linker) addLibrary(name string, kind inputKind, lib Library, closer interface{ Close() error }) error {
	// A library named twice is one library. The link line commonly repeats
	// -lSystem through several driver layers, and adding it twice would
	// produce two load commands, two ordinals, and a symbol that resolves to
	// whichever came first.
	for _, prev := range l.libs {
		if prev.lib.InstallName() == lib.InstallName() {
			return nil
		}
	}
	in := &inputFile{name: name, kind: kind, lib: lib, closer: closer}
	l.inputs = append(l.inputs, in)
	l.libs = append(l.libs, in)
	return nil
}

// checkTarget rejects an input built for something else.
//
// The cpusubtype is compared with Base(), so an arm64e object's ptrauth
// capability bits do not make it a different architecture from the target —
// but arm64 and arm64e themselves are different subtypes and do not mix.
func (l *Linker) checkTarget(name string, t macho.Target) error {
	if t.CPU != l.target.CPU || t.SubCPU.Base() != l.target.SubCPU.Base() {
		return fmt.Errorf("%w: %s is %s, the target is %s",
			ErrCPUMismatch, name, macho.ArchName(t.CPU, t.SubCPU), l.target.Arch())
	}
	if t.Platform != macho.PlatformUnknown && t.Platform != l.target.Platform {
		// A simulator, a device, and Mac Catalyst are distinct platforms, not
		// a flag on one, and mixing them produces an image dyld will refuse.
		return fmt.Errorf("%w: %s is for %v, the target is %v",
			ErrPlatformMismatch, name, t.Platform, l.target.Platform)
	}
	if t.MinOS != 0 && t.MinOS > l.target.MinOS {
		return fmt.Errorf("%w: %s requires %v, the target's minimum is %v",
			ErrPlatformMismatch, name, t.MinOS, l.target.MinOS)
	}
	return nil
}

// Close releases every input this Linker opened.
func (l *Linker) Close() error {
	var first error
	for _, in := range l.inputs {
		if in.closer == nil {
			continue
		}
		if err := in.closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// stubLibrary adapts a parsed .tbd to the Library interface.
type stubLibrary struct {
	s *tbd.Stub

	// reexported holds every transitively re-exported library's stub, keyed
	// by install name and resolved once by resolveReexports rather than
	// walked again on every Exports call.
	//
	// libSystem.tbd defines almost nothing itself: real symbols like _getpid
	// or _malloc live in libsystem_kernel.dylib and libsystem_c.dylib, which
	// it re-exports rather than restates. A two-level namespace link that
	// only sees libSystem's own exports resolves almost nothing a real
	// program calls, which is why this exists.
	reexported map[string]*tbd.Stub
}

func (l *stubLibrary) InstallName() string            { return l.s.InstallName }
func (l *stubLibrary) CurrentVersion() macho.Version  { return l.s.CurrentVersion }
func (l *stubLibrary) CompatVersion() macho.Version   { return l.s.CompatVersion }
func (l *stubLibrary) Clients(t macho.Target) []string { return l.s.Clients(t) }

// resolveReexports walks this stub's re-exported libraries to a fixpoint,
// finding each one's own stub either inlined in the same .tbd file — the
// common case for an umbrella like libSystem.tbd, which bundles every library
// it re-exports as extra YAML documents in one file — or, failing that, under
// sdk by install name. sdk may be empty, in which case only inlined stubs are
// found.
//
// A library a real SDK does not ship a stub for, or which resolveReexports
// simply cannot find, is skipped rather than failing the whole link: most
// programs never reference its symbols, and a link that fails on every
// unrelated re-export would be unusable.
func (l *stubLibrary) resolveReexports(t macho.Target, sdk string) {
	l.reexported = make(map[string]*tbd.Stub)
	seen := map[string]bool{l.s.InstallName: true}
	queue := append([]string(nil), l.s.ReexportedLibraries(t)...)

	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true

		sub := l.s.Find(name)
		if sub == nil && sdk != "" {
			sub, _ = loadStubFromSDK(sdk, name)
		}
		if sub == nil {
			continue
		}
		l.reexported[name] = sub
		queue = append(queue, sub.ReexportedLibraries(t)...)
	}
}

// loadStubFromSDK reads the .tbd for a re-exported library's install name
// from under an SDK root, e.g. "/usr/lib/system/libsystem_kernel.dylib"
// becomes "<sdk>/usr/lib/system/libsystem_kernel.tbd".
func loadStubFromSDK(sdk, installName string) (*tbd.Stub, error) {
	rel := strings.TrimSuffix(installName, filepath.Ext(installName)) + ".tbd"
	data, err := os.ReadFile(filepath.Join(sdk, rel))
	if err != nil {
		return nil, err
	}
	return tbd.Parse(data)
}

// Exports returns the stub's exported and re-exported symbols together,
// including everything reachable through resolveReexports.
//
// They are merged here because both are names this library's ordinal binds,
// which is all resolution cares about. The distinction matters only to a
// diagnostic that wants to say where a definition actually lives, and that
// belongs to the error path rather than to the lookup.
func (l *stubLibrary) Exports(t macho.Target) []Export {
	seen := make(map[string]bool)
	var out []Export
	add := func(syms []tbd.Symbol) {
		for _, s := range syms {
			if seen[s.Name] {
				continue
			}
			seen[s.Name] = true
			out = append(out, Export{
				Name:        s.Name,
				Weak:        s.Kind == tbd.Weak,
				ThreadLocal: s.Kind == tbd.ThreadLocal,
			})
		}
	}
	add(l.s.Exports(t))
	add(l.s.Reexported(t))
	for _, sub := range l.reexported {
		add(sub.Exports(t))
		add(sub.Reexported(t))
	}
	return out
}

func (l *stubLibrary) Reexports(t macho.Target) []string {
	return l.s.ReexportedLibraries(t)
}