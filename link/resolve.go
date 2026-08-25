package link

import (
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/image"
	"github.com/vertex-language/macho/obj"
)

// Symbol resolution.
//
// # The archive fixpoint
//
// Traditional Unix linkers search archives once, in command-line order, which
// is why a static library sometimes has to be listed twice. ld does not work
// that way: it re-searches every archive whenever anything new becomes
// undefined, so ordering on the command line does not affect what gets pulled
// in. This implementation matches that, and the loop below is the reason.
//
// The loop terminates because extraction is monotonic — a member is extracted
// at most once, and there are finitely many members — not because of any bound
// on iterations.
//
// # What resolution does not do
//
// It does not create atoms. Splitting an object into atoms is step 2, and it
// needs to know which definitions survived resolution before it can decide
// which sections to split at all. Resolution therefore records, for each
// symbol, the input and the nlist entry that defines it, and split attaches
// the atom afterwards.

// resolution is the state resolve builds up.
type resolution struct {
	// def maps a symbol to the definition that won.
	def map[*image.Sym]definition

	// refs records where each symbol was referenced, for diagnostics. Only
	// undefined symbols ever need this, but which symbols end up undefined is
	// not known until the end, so it is recorded for all of them.
	refs map[*image.Sym][]Reference

	// pending indexes archive members by the symbols they define, for members
	// not yet extracted.
	pending map[string][]archiveMember

	// extracted records which members have been pulled in, so a member
	// defining several needed symbols is extracted once.
	extracted map[archiveMember]bool
}

// definition is the winning definition of a symbol.
type definition struct {
	input *inputFile

	// sym is the nlist entry, for a definition from an object.
	sym *obj.Symbol

	// lib is the library, for an imported definition.
	lib Library
}

// archiveMember identifies one member of one archive.
type archiveMember struct {
	in   *inputFile
	name string
	off  int64 // header offset, which is what the table of contents stores
}

func (r *resolution) init() {
	r.def = make(map[*image.Sym]definition)
	r.refs = make(map[*image.Sym][]Reference)
	r.pending = make(map[string][]archiveMember)
	r.extracted = make(map[archiveMember]bool)
}

// resolve builds the symbol table and decides every definition.
func (l *Linker) resolve(img *image.Image) error {
	syms := img.Symbols()

	// Seed the archive index before anything else, so that a symbol first
	// referenced by the very first object can pull a member immediately.
	if err := l.indexArchives(); err != nil {
		return err
	}

	// -u names symbols that must exist. Interning them undefined is what
	// makes the fixpoint go looking for them, which is the whole purpose of
	// the option: forcing a member out of a library nothing else references.
	for _, name := range l.opts.Undefineds {
		syms.Intern(name)
	}
	if l.opts.Output == OutputExecute {
		syms.Intern(l.opts.Entry)
	}

	// Objects named on the command line are loaded unconditionally, in order.
	for _, in := range l.inputs {
		switch in.kind {
		case inputObject:
			if err := l.loadObject(img, in); err != nil {
				return err
			}
		case inputArchive:
			if in.forced {
				if err := l.loadWholeArchive(img, in); err != nil {
					return err
				}
			}
		}
	}

	// The fixpoint. Each round extracts every archive member that satisfies a
	// currently undefined symbol; extracting one can create new undefined
	// symbols, so the round repeats until nothing moves.
	for {
		extracted, err := l.extractRound(img)
		if err != nil {
			return err
		}
		if !extracted {
			break
		}
	}

	// Libraries are consulted after archives, not before. A definition in an
	// object or an archive member wins over one in a dylib — otherwise a
	// program could never override a library function, which is a thing
	// programs legitimately do.
	if err := l.bindLibraries(img); err != nil {
		return err
	}

	l.resolveCommons(img)
	l.applyExportRules(img)
	return l.assignOrdinals(img)
}

// indexArchives records which members define which symbols, without reading
// any member.
//
// The table of contents is enough for this, which is the point of having one:
// deciding whether an archive can satisfy a symbol costs a map lookup rather
// than parsing every member's symbol table.
func (l *Linker) indexArchives() error {
	for _, in := range l.inputs {
		if in.kind != inputArchive || in.forced {
			continue
		}
		toc, err := in.ar.TOC()
		if err != nil {
			return fmt.Errorf("link: %s: %w", in.name, err)
		}
		for _, e := range toc.Entries {
			m := archiveMember{in: in, name: e.Symbol, off: e.MemberHeaderOffset}
			l.res.pending[e.Symbol] = append(l.res.pending[e.Symbol], m)
		}
	}
	return nil
}

// extractRound pulls in every archive member that satisfies something
// currently undefined. It reports whether it extracted anything.
func (l *Linker) extractRound(img *image.Image) (bool, error) {
	undef := img.Symbols().Undefined()
	if len(undef) == 0 {
		return false, nil
	}

	// Sort the work by name so that two runs over the same inputs extract
	// members in the same order. Extraction order decides the order atoms are
	// created, which decides layout — so without this the linker would not be
	// reproducible.
	names := make([]string, 0, len(undef))
	for _, s := range undef {
		names = append(names, s.Name)
	}
	sort.Strings(names)

	any := false
	for _, name := range names {
		for _, m := range l.res.pending[name] {
			if l.res.extracted[m] {
				continue
			}
			l.res.extracted[m] = true
			if err := l.extract(img, m); err != nil {
				return false, err
			}
			any = true
		}
	}
	return any, nil
}

// extract parses one archive member and loads its definitions.
func (l *Linker) extract(img *image.Image, m archiveMember) error {
	var member *ar.Member
	for _, cand := range m.in.ar.Members {
		if cand.HeaderOffset == m.off {
			member = cand
			break
		}
	}
	if member == nil {
		return fmt.Errorf("link: %s: table of contents names offset %d, which is no member's header",
			m.in.name, m.off)
	}
	ext, err := member.Extent()
	if err != nil {
		return fmt.Errorf("link: %s(%s): %w", m.in.name, member.Name, err)
	}
	f, err := obj.NewFile(ext)
	if err != nil {
		return fmt.Errorf("link: %s(%s): %w", m.in.name, member.Name, err)
	}
	in := &inputFile{
		name: fmt.Sprintf("%s(%s)", m.in.name, member.Name),
		kind: inputObject,
		obj:  f,
	}
	if err := l.checkTarget(in.name, f.Target()); err != nil {
		return err
	}
	l.inputs = append(l.inputs, in)
	return l.loadObject(img, in)
}

// loadWholeArchive extracts every member, for -all_load and -force_load.
func (l *Linker) loadWholeArchive(img *image.Image, in *inputFile) error {
	for _, m := range in.ar.Members {
		key := archiveMember{in: in, name: m.Name, off: m.HeaderOffset}
		if l.res.extracted[key] {
			continue
		}
		l.res.extracted[key] = true
		if err := l.extract(img, key); err != nil {
			return err
		}
	}
	return nil
}

// loadObject records every symbol an object defines and references.
func (l *Linker) loadObject(img *image.Image, in *inputFile) error {
	syms, err := in.obj.Symbols()
	if err != nil {
		if err == obj.ErrNoSymbolTable {
			// A stripped object is legal. It contributes content and no
			// names, which is unusual but not wrong.
			return nil
		}
		return fmt.Errorf("link: %s: %w", in.name, err)
	}

	table := img.Symbols()
	for _, s := range syms {
		// A stab is debug information, not a linkage symbol. Its n_type byte
		// is a value from stab.h and the N_TYPE mask does not apply, so
		// treating it as a definition would produce nonsense.
		if s.Stab() || !s.Ext() {
			continue
		}

		sym := table.Intern(s.Name)
		switch {
		case s.Undefined() && !s.Common():
			l.res.refs[sym] = append(l.res.refs[sym], Reference{Input: in.name})
			if s.WeakRef() {
				sym.WeakRef = true
			}

		case s.Common():
			// A tentative definition. It does not win against a real one and
			// it does not lose to another tentative definition of smaller
			// size, so it is recorded and settled later.
			if sym.Class == image.ClassUndefined {
				sym.Class = image.ClassCommon
				sym.Value = s.Value
				sym.Input = l.imageInput(img, in)
				l.res.def[sym] = definition{input: in, sym: s}
			} else if sym.Class == image.ClassCommon && s.Value > sym.Value {
				sym.Value = s.Value
				l.res.def[sym] = definition{input: in, sym: s}
			}

		default:
			if err := l.define(sym, in, s); err != nil {
				return err
			}
			sym.Input = l.imageInput(img, in)
		}
	}
	return nil
}

// define records a real definition, resolving any contest with an existing
// one.
//
// The rules, in order:
//
//   - A real definition beats a tentative one and beats an import.
//   - A strong definition beats a weak one. The weak one's atom is marked
//     Coalesced, which is permanent and independent of dead-stripping: it
//     stays referenceable, and references to it get redirected to the winner
//     rather than the atom being resurrected.
//   - Two weak definitions: the first wins. There is no better rule — they are
//     by construction interchangeable — and "first" is deterministic given
//     that extraction order is deterministic.
//   - Two strong definitions is a DuplicateError.
func (l *Linker) define(sym *image.Sym, in *inputFile, s *obj.Symbol) error {
	weak := s.WeakDef()

	switch sym.Class {
	case image.ClassUndefined, image.ClassCommon, image.ClassImport:
		// Nothing real yet: take it.

	case image.ClassDefined, image.ClassAbsolute:
		prev := l.res.def[sym]
		switch {
		case sym.WeakDef && !weak:
			// The incoming strong definition displaces the weak one.
			l.coalesce(sym, prev)
		case weak:
			// Either the existing definition is strong, or both are weak and
			// the first stays. Either way this one loses.
			l.coalesceInput(sym, definition{input: in, sym: s})
			return nil
		default:
			return &DuplicateError{
				Name:  sym.Name,
				First: Reference{Input: prev.input.name, Atom: sym.Name},
				Again: Reference{Input: in.name, Atom: sym.Name},
			}
		}
	}

	sym.Class = image.ClassDefined
	if s.Absolute() {
		sym.Class = image.ClassAbsolute
		sym.Value = s.Value
		sym.Bound = true
	}
	sym.WeakDef = weak
	sym.Private = s.Pext()
	sym.ThreadLocal = false
	sym.Root = s.NoDeadStrip() || s.ReferencedDynamically()
	l.res.def[sym] = definition{input: in, sym: s}
	return nil
}

// coalesce and coalesceInput record a definition that lost a weak election.
//
// Nothing can be marked on an atom yet, since atoms do not exist until split.
// The losing definitions are therefore accumulated and split consults them —
// which is why they are keyed by the (input, nlist) pair rather than by symbol.
func (l *Linker) coalesce(sym *image.Sym, lost definition)      { l.res.lost(sym, lost) }
func (l *Linker) coalesceInput(sym *image.Sym, lost definition) { l.res.lost(sym, lost) }

// lost records a coalesced-away definition.
func (r *resolution) lost(sym *image.Sym, d definition) {
	if r.coalesced == nil {
		r.coalesced = make(map[definition]*image.Sym)
	}
	r.coalesced[d] = sym
}

// bindLibraries resolves what is left against the dylib and stub inputs.
//
// Under a two-level namespace only the libraries named on the link line are
// searched, plus whatever they re-export. Indirect libraries — the ones those
// libraries themselves link against — are invisible, which is the whole point:
// the recorded ordinal must name a library the image actually loads.
func (l *Linker) bindLibraries(img *image.Image) error {
	table := img.Symbols()

	for _, in := range l.libs {
		if err := l.checkClients(in); err != nil {
			return err
		}
		for _, e := range in.lib.Exports(l.target) {
			sym := table.Find(e.Name)
			if sym == nil || sym.Class != image.ClassUndefined {
				// Not referenced, or already defined by an object. A
				// definition in this image always wins over a library's:
				// that is what lets a program override a library function.
				continue
			}
			sym.Class = image.ClassImport
			sym.WeakDef = e.Weak
			sym.ThreadLocal = e.ThreadLocal
			sym.Input = l.imageInput(img, in)
			in.used = true
			l.res.def[sym] = definition{input: in, lib: in.lib}
		}
	}

	// -U names symbols allowed to go unresolved, and dynamic_lookup says the
	// same of all of them. Either way the ordinal is DYNAMIC_LOOKUP_ORDINAL
	// and dyld searches every loaded image at runtime.
	allow := make(map[string]bool, len(l.opts.AllowUndefined))
	for _, n := range l.opts.AllowUndefined {
		allow[n] = true
	}
	for _, sym := range table.Undefined() {
		if allow[sym.Name] || l.opts.Undefined == UndefinedDynamicLookup {
			sym.Class = image.ClassImport
			sym.Ordinal = macho.DYNAMIC_LOOKUP_ORDINAL
		}
	}
	return nil
}

// checkClients enforces a library's allowable-client list.
func (l *Linker) checkClients(in *inputFile) error {
	clients := in.lib.Clients(l.target)
	if len(clients) == 0 {
		return nil
	}
	// The degenerate "!" entry means nothing may link against this library.
	self := l.opts.InstallName
	for _, c := range clients {
		if c == self {
			return nil
		}
	}
	return fmt.Errorf("link: %s restricts its clients and %q is not one of them",
		in.lib.InstallName(), self)
}

// resolveCommons turns surviving tentative definitions into real ones.
//
// The default treatment does not consult dylibs at all, which is worth
// restating because it surprises people: a common symbol in an object beats an
// exported definition of the same name in a linked library, silently. That
// matches ld64's -commons ignore_dylibs default.
func (l *Linker) resolveCommons(img *image.Image) {
	for _, sym := range img.Symbols().All() {
		if sym.Class != image.ClassCommon {
			continue
		}
		// The storage itself is created during split, as a zerofill atom in
		// __DATA,__common sized by the value recorded here.
		sym.Class = image.ClassDefined
	}
}

// applyExportRules decides which defined symbols reach the export trie.
//
// An explicit exported-symbols list is exhaustive: everything absent from it
// is demoted to a private extern, which is what the option means. Without one,
// every non-private global is exported from a dylib, and an executable exports
// nothing unless something asks it to.
func (l *Linker) applyExportRules(img *image.Image) {
	exported := make(map[string]bool, len(l.opts.ExportedSymbols))
	for _, n := range l.opts.ExportedSymbols {
		exported[n] = true
	}
	unexported := make(map[string]bool, len(l.opts.UnexportedSymbols))
	for _, n := range l.opts.UnexportedSymbols {
		unexported[n] = true
	}

	dylibLike := l.opts.Output == OutputDylib || l.opts.Output == OutputBundle

	for _, sym := range img.Symbols().All() {
		if !sym.Defined() {
			continue
		}
		switch {
		case len(exported) > 0:
			sym.Exported = exported[sym.Name]
			sym.Private = !sym.Exported
		case unexported[sym.Name]:
			sym.Exported = false
			sym.Private = true
		default:
			sym.Exported = dylibLike && !sym.Private
		}
		// An exported symbol is a dead-strip root: something outside this
		// image may call it, and nothing in the image's own reference graph
		// would keep it alive.
		if sym.Exported {
			sym.Root = true
		}
	}
}

// assignOrdinals gives each library its two-level namespace ordinal.
//
// Ordinals index the LC_LOAD_DYLIB commands in the order they appear, starting
// at 1, so this must run after the set of libraries is final and must produce
// the same order the emitter writes them in.
func (l *Linker) assignOrdinals(img *image.Image) error {
	if l.opts.Namespace == NamespaceFlat {
		// Flat namespace records no ordinal. Every import binds with
		// SELF_LIBRARY_ORDINAL and dyld searches all images at runtime.
		return nil
	}
	if len(l.libs) > int(macho.MAX_LIBRARY_ORDINAL) {
		return &TooManyDylibsError{Count: len(l.libs)}
	}

	n := macho.LibOrdinal(0)
	for _, in := range l.libs {
		if l.opts.DeadStripDylibs && !in.used {
			continue
		}
		n++
		in.ordinal = n
	}

	for sym, d := range l.res.def {
		if sym.Class != image.ClassImport || sym.Ordinal == macho.DYNAMIC_LOOKUP_ORDINAL {
			continue
		}
		if d.lib == nil {
			continue
		}
		for _, in := range l.libs {
			if in.lib == d.lib {
				sym.Ordinal = in.ordinal
				break
			}
		}
	}

	// A bundle's undefined symbols may resolve against the executable that
	// will load it, which is a distinct reserved ordinal rather than a
	// library index — the executable has no load command to point at.
	if l.opts.Output == OutputBundle && l.opts.BundleLoader != "" {
		for _, sym := range img.Symbols().All() {
			if sym.Class == image.ClassImport && sym.Ordinal == 0 {
				sym.Ordinal = macho.EXECUTABLE_ORDINAL
			}
		}
	}
	return nil
}

// checkUndefined reports anything still lacking a definition.
func (l *Linker) checkUndefined(img *image.Image) error {
	undef := img.Symbols().Undefined()
	if len(undef) == 0 {
		return nil
	}
	switch l.opts.Undefined {
	case UndefinedSuppress:
		return nil
	case UndefinedWarning:
		for _, sym := range undef {
			l.warn(&UndefinedError{Name: sym.Name, Refs: l.res.refs[sym]})
		}
		return nil
	}
	// Report the first, with everything known about it. Reporting all of them
	// is usually noise: one missing library produces hundreds.
	sort.Slice(undef, func(i, j int) bool { return undef[i].Name < undef[j].Name })
	return &UndefinedError{Name: undef[0].Name, Refs: l.res.refs[undef[0]]}
}

// imageInput returns the image.Input for a link input, creating it on first
// use so that inputs contributing nothing never appear in the output.
func (l *Linker) imageInput(img *image.Image, in *inputFile) *image.Input {
	if in.imgInput != nil {
		return in.imgInput
	}
	kind := image.InputObject
	switch in.kind {
	case inputArchive:
		kind = image.InputArchiveMember
	case inputDylib:
		kind = image.InputDylib
	case inputStub:
		kind = image.InputStub
	}
	ii := &image.Input{Name: in.name, Kind: kind}
	if in.lib != nil {
		ii.InstallName = in.lib.InstallName()
	}
	_ = img.AddInput(ii)
	in.imgInput = ii
	return ii
}

// warn reports a non-fatal diagnostic.
func (l *Linker) warn(err error) {
	if l.Warn != nil {
		l.Warn(err)
	}
}