package link

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
)

// Linker performs one link.
//
// A Linker is single-use and is not safe for concurrent use. Link may be
// called once; calling it again returns the first call's error.
type Linker struct {
	target macho.Target
	opts   Options
	be     backend.Backend
	reqs   *backend.Reqs

	inputs []*inputFile

	// libs are the dylib and stub inputs in the order they were added, which
	// is the order their load commands appear and therefore the order their
	// ordinals are assigned.
	libs []*inputFile

	// res is the resolution state: what defines what, and which archive
	// members are still pending extraction.
	res resolution

	// sdk is the root the .tbd stubs for system libraries are found under.
	sdk string

	done bool
	err  error
}

// New returns a Linker for a target.
//
// The backend is looked up here rather than at Link, so that a missing
// architecture package fails immediately instead of after every input has been
// read.
func New(t macho.Target) (*Linker, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("%w: %v", macho.ErrInvalidTarget, t)
	}
	be, err := backend.For(t)
	if err != nil {
		return nil, err
	}
	l := &Linker{target: t, be: be, reqs: backend.NewReqs()}
	l.opts.defaults()
	l.res.init()
	return l, nil
}

// Target returns the link target.
func (l *Linker) Target() macho.Target { return l.target }

// Backend returns the backend serving this link.
func (l *Linker) Backend() backend.Backend { return l.be }

// Options returns the configuration, for direct modification:
//
//	l.Options().Output = link.OutputDylib
//
// Changes after Link has run have no effect.
func (l *Linker) Options() *Options { return &l.opts }

// fail latches the first error. Everything after it becomes a no-op, in the
// same style as obj.Writer and binio.Buf, so a caller that ignores
// intermediate results still gets the original cause from Link.
func (l *Linker) fail(err error) {
	if l.err == nil && err != nil {
		l.err = err
	}
}

// Err returns the first error the link hit, or nil.
func (l *Linker) Err() error { return l.err }

// Configuration setters.
//
// These are what replaces a linker script. Each is a thin wrapper over an
// Options field; they exist because a call reads better at a build system's
// call site than a struct literal spread across twenty lines, and because a
// few of them validate.

func (l *Linker) SetEntry(sym string)          { l.opts.Entry = sym }
func (l *Linker) SetInstallName(path string)   { l.opts.InstallName = path }
func (l *Linker) SetBundleLoader(path string)  { l.opts.BundleLoader = path }
func (l *Linker) SetPageZeroSize(n uint64)     { l.opts.PageZeroSize = n }
func (l *Linker) SetOrderFile(syms []string)   { l.opts.OrderFile = append([]string(nil), syms...) }
func (l *Linker) SetExportedSymbols(s []string) { l.opts.ExportedSymbols = append([]string(nil), s...) }
func (l *Linker) KeepPrivateExterns(v bool)    { l.opts.KeepPrivateExterns = v }
func (l *Linker) DeadStrip(v bool)             { l.opts.DeadStrip = v }
func (l *Linker) LoadAllObjC(v bool)           { l.opts.LoadAllObjC = v }
func (l *Linker) ForceLoad(path string)        { l.opts.ForceLoad = append(l.opts.ForceLoad, path) }
func (l *Linker) AddRPath(p string)            { l.opts.RPaths = append(l.opts.RPaths, p) }
func (l *Linker) SetSDK(root string)           { l.sdk = root }

func (l *Linker) SetUndefinedTreatment(t UndefinedTreatment) { l.opts.Undefined = t }
func (l *Linker) SetNamespace(n Namespace)                   { l.opts.Namespace = n }

// SetDylibVersions sets the current and compatibility versions.
func (l *Linker) SetDylibVersions(current, compat macho.Version) {
	l.opts.CurrentVersion, l.opts.CompatVersion = current, compat
}

// SetSegmentAddress pins a segment's vmaddr.
func (l *Linker) SetSegmentAddress(seg string, addr uint64) {
	if l.opts.SegmentAddress == nil {
		l.opts.SegmentAddress = make(map[string]uint64)
	}
	l.opts.SegmentAddress[seg] = addr
}

// SetSegmentProt overrides a segment's protections.
func (l *Linker) SetSegmentProt(seg string, max, init macho.Prot) {
	if l.opts.SegmentProt == nil {
		l.opts.SegmentProt = make(map[string]ProtPair)
	}
	l.opts.SegmentProt[seg] = ProtPair{Max: max, Init: init}
}

// AddSectionData injects raw bytes as a section, the equivalent of
// -sectcreate. The pair must not collide with a section from any input.
func (l *Linker) AddSectionData(segment, section string, data []byte) {
	n := macho.Sec(segment, section)
	if !n.Valid() {
		l.fail(fmt.Errorf("link: section name %s does not fit its 16-byte fields", n))
		return
	}
	if l.opts.SectionData == nil {
		l.opts.SectionData = make(map[macho.SecName][]byte)
	}
	if _, dup := l.opts.SectionData[n]; dup {
		l.fail(fmt.Errorf("link: %s given twice with -sectcreate", n))
		return
	}
	l.opts.SectionData[n] = data
}

// Link runs the pipeline and returns the finished image.
//
// The sequence is fixed. Two steps of it differ from an ELF linker's for
// reasons specific to Mach-O:
//
// __TEXT begins at file offset 0 and contains the header and the load
// commands, so the size of the load-command block is an input to address
// assignment rather than something computed after it. That closes a loop, and
// the loop has to converge inside the layout fixpoint.
//
// The code signature hashes the file from offset zero to the start of the
// signature, so it covers the header, the load commands, and every segment.
// It must therefore run after the last byte of everything else is final, which
// is why Finalize is a distinct phase and not part of emit.
func (l *Linker) Link() (*image.Image, error) {
	if l.done {
		return nil, l.err
	}
	l.done = true

	if l.err != nil {
		return nil, l.err
	}
	l.opts.defaults()
	if err := l.opts.Validate(); err != nil {
		return nil, err
	}
	if len(l.inputs) == 0 {
		return nil, ErrNoInputs
	}
	if len(l.libs) == 0 {
		return nil, ErrNoLibSystem
	}

	img := image.New(l.target)
	if err := img.SetOptions(image.Options{
		FileType:     l.opts.Output.FileType(),
		Flags:        l.headerFlags(),
		PageSize:     l.opts.PageSize,
		PageZeroSize: l.opts.PageZeroSize,
		NoPageZero:   !l.opts.hasPageZero(),
	}); err != nil {
		return nil, err
	}
	if err := img.AddReserved(); err != nil {
		return nil, err
	}

	// 1. Symbols, the archive fixpoint, weak definitions, and library
	//    ordinals.
	if err := l.resolve(img); err != nil {
		return nil, err
	}

	// 2-12. The rest of the pipeline. Each of these lands in its own file;
	//       see the stubs at the bottom of this one for what is not written
	//       yet.
	for _, step := range []struct {
		name string
		run  func(*image.Image) error
	}{
		{"split", l.split},
		{"sweep", l.sweep},
		{"check undefined", l.checkUndefined},
		{"merge", l.merge},
		{"scan", l.scan},
		{"order", l.order},
		{"layout", l.layout},
		{"contents", l.contents},
		{"unwind", l.unwind},
		{"fixups", l.fixups},
		{"linkedit", l.linkedit},
		{"emit", l.emit},
		{"finalize", l.finalize},
	} {
		if err := step.run(img); err != nil {
			return nil, fmt.Errorf("link: %s: %w", step.name, err)
		}
	}
	return img, nil
}

// headerFlags computes the header flags for the output.
func (l *Linker) headerFlags() macho.Flags {
	f := l.opts.Flags | macho.MH_DYLDLINK | macho.MH_NOUNDEFS
	if l.opts.Namespace == NamespaceTwoLevel {
		f |= macho.MH_TWOLEVEL
	}
	if l.opts.Output == OutputExecute {
		// PIE is the default on every platform this tree targets, and on
		// arm64 it is not optional — the kernel will not load a non-PIE
		// arm64 executable.
		f |= macho.MH_PIE
	}
	if l.opts.Undefined == UndefinedDynamicLookup || l.opts.Namespace == NamespaceFlat {
		// Undefined symbols will remain in the output, so the flag asserting
		// there are none would be a lie dyld acts on.
		f &^= macho.MH_NOUNDEFS
	}
	return f
}

// --------------------------------------------------------------------------
// Pipeline steps not yet written.
//
// These are declared here so the package compiles and the sequence in Link
// reads as the whole pipeline rather than the part that happens to exist. Each
// moves to its own file as it is implemented — delete the stub here when you
// add the real method, or the compiler will report a redeclaration, which is
// the intended reminder.
// --------------------------------------------------------------------------

func (l *Linker) split(*image.Image) error {
	return fmt.Errorf("%w: split.go", ErrUnimplemented)
}
func (l *Linker) sweep(*image.Image) error  { return fmt.Errorf("%w: sweep.go", ErrUnimplemented) }
func (l *Linker) merge(*image.Image) error  { return fmt.Errorf("%w: merge.go", ErrUnimplemented) }
func (l *Linker) order(*image.Image) error  { return fmt.Errorf("%w: order.go", ErrUnimplemented) }
func (l *Linker) layout(*image.Image) error { return fmt.Errorf("%w: assign.go", ErrUnimplemented) }
func (l *Linker) contents(*image.Image) error {
	return fmt.Errorf("%w: apply.go", ErrUnimplemented)
}
func (l *Linker) unwind(*image.Image) error   { return fmt.Errorf("%w: unwind.go", ErrUnimplemented) }
func (l *Linker) fixups(*image.Image) error   { return fmt.Errorf("%w: fixups.go", ErrUnimplemented) }
func (l *Linker) linkedit(*image.Image) error { return fmt.Errorf("%w: linkedit.go", ErrUnimplemented) }
func (l *Linker) emit(*image.Image) error     { return fmt.Errorf("%w: emit.go", ErrUnimplemented) }
func (l *Linker) finalize(*image.Image) error {
	return fmt.Errorf("%w: image.Finalize wiring", ErrUnimplemented)
}

// scan is the backend's sizing pass. It is a one-liner and is here rather than
// in its own file.
func (l *Linker) scan(img *image.Image) error { return l.be.Scan(img, l.reqs) }