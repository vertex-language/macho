// Package tbd reads text-based dynamic library stubs.
//
// A .tbd file describes a dylib's exported surface without carrying its code.
// Reading them is not optional for a linker on Apple platforms: the system
// libraries live in the dyld shared cache and are not present in the SDK as
// Mach-O files at all, so an ordinary program cannot be linked without them.
//
// Versions 1 through 4 are handled. Version 5 is JSON with a different key set
// entirely; it is detected and rejected rather than half-parsed, because a
// stub that parses to an empty export list produces an undefined-symbol error
// naming the symbol rather than the file, which is the wrong place to start
// debugging.
//
// The YAML reader is a hand-written subset parser rather than a dependency;
// see yaml.go for what it accepts.
package tbd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vertex-language/macho"
)

var (
	// ErrUnsupportedTBDVersion means the file is v5 (JSON), or carries a
	// document tag this package does not recognize.
	ErrUnsupportedTBDVersion = errors.New("tbd: unsupported .tbd version")

	// ErrNoMatchingTarget means the stub has no export list for the requested
	// architecture and platform.
	ErrNoMatchingTarget = errors.New("tbd: no export list for the requested target")

	// ErrMalformed means a required key was missing or a value could not be
	// read.
	ErrMalformed = errors.New("tbd: malformed stub library")
)

// Flags are the document-level flags a stub may carry.
type Flags uint8

const (
	// FlatNamespace means the library was built without the two-level
	// namespace. An undefined symbol from it names no library, so a link
	// against it loses the ordinal that makes UndefinedError able to say where
	// a symbol was expected from.
	FlatNamespace Flags = 1 << iota

	// NotAppExtensionSafe means an app extension may not link against it.
	NotAppExtensionSafe

	// InstallAPI means the stub was generated from headers rather than from a
	// built library, so its symbol list is a promise about the source rather
	// than an observation of a binary.
	InstallAPI
)

func (f Flags) Has(g Flags) bool { return f&g == g }

// Stub is one parsed .tbd document.
type Stub struct {
	// Version is the TBD format version, 1 through 4.
	Version int

	InstallName    string
	CurrentVersion macho.Version
	CompatVersion  macho.Version
	SwiftABI       int
	Flags          Flags
	ParentUmbrella string

	// Targets is every architecture-platform pair the stub covers.
	Targets []Target

	// UUIDs maps a target's string form to its UUID, best effort. The three
	// format versions spell this key three different ways and nothing in a
	// link depends on it, so an unreadable entry is skipped rather than fatal.
	UUIDs map[string]string

	// Inlined holds the remaining documents of a multi-document file. Private
	// framework inlining puts a public library first and the private
	// frameworks it re-exports after it, so a linker that follows a re-export
	// finds the target without opening another file.
	Inlined []*Stub

	exports    []section
	reexports  []section
	undefineds []section

	// libs are the v4 document-level reexported-libraries groups. Pre-v4 files
	// carry the same information per export section, and decode normalizes
	// both into this.
	libs []libGroup

	// clients are the allowable-clients groups, likewise normalized.
	clients []clientGroup
}

// section is one export, re-export, or undefined group.
type section struct {
	targets []Target

	symbols     []string
	weak        []string
	threadLocal []string
	objcClasses []string
	objcEHTypes []string
	objcIvars   []string
}

type libGroup struct {
	targets []Target
	libs    []string
}

type clientGroup struct {
	targets []Target
	clients []string
}

// Parse reads a stub library.
//
// It returns the file's first document; any further documents are inlined
// private frameworks and hang off Inlined.
func Parse(data []byte) (*Stub, error) {
	stubs, err := ParseAll(data)
	if err != nil {
		return nil, err
	}
	if len(stubs) == 0 {
		return nil, fmt.Errorf("%w: file contains no documents", ErrMalformed)
	}
	stubs[0].Inlined = stubs[1:]
	return stubs[0], nil
}

// ParseAll reads every document in a stub library, flat.
func ParseAll(data []byte) ([]*Stub, error) {
	// v5 is JSON. Detecting it on the leading brace is enough — a YAML TBD
	// always begins with "---" or a key — and naming the version in the error
	// is the whole point, since the alternative is a YAML parse failure on
	// line 1 that says nothing useful.
	if trimmed := strings.TrimLeft(string(data), " \t\r\n"); strings.HasPrefix(trimmed, "{") {
		return nil, fmt.Errorf("%w: this is a v5 (JSON) file", ErrUnsupportedTBDVersion)
	}

	tags, docs, err := parseDocuments(data)
	if err != nil {
		return nil, err
	}

	out := make([]*Stub, 0, len(docs))
	for i, doc := range docs {
		if doc == nil {
			continue
		}
		s, err := decode(tags[i], doc)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// decode turns one parsed document into a Stub.
func decode(tag string, doc *node) (*Stub, error) {
	s := &Stub{UUIDs: make(map[string]string)}

	switch tag {
	case "!tapi-tbd":
		s.Version = 4
	case "!tapi-tbd-v3":
		s.Version = 3
	case "!tapi-tbd-v2":
		s.Version = 2
	case "!tapi-tbd-v1", "":
		// v1 has no tag; the tag is optional there precisely so that older
		// linkers keep reading the file.
		s.Version = 1
	default:
		return nil, fmt.Errorf("%w: document tag %q", ErrUnsupportedTBDVersion, tag)
	}
	if s.Version == 4 {
		v := doc.get("tbd-version").text()
		if v != "" && v != "4" {
			return nil, fmt.Errorf("%w: tbd-version %s under the !tapi-tbd tag",
				ErrUnsupportedTBDVersion, v)
		}
	}

	s.InstallName = doc.get("install-name").text()
	if s.InstallName == "" {
		return nil, fmt.Errorf("%w: no install-name", ErrMalformed)
	}

	// current-version and compatibility-version default to 1.0 when absent,
	// which is what the format says and what a dylib without them would carry.
	var err error
	if s.CurrentVersion, err = version(doc.get("current-version"), "current-version"); err != nil {
		return nil, err
	}
	if s.CompatVersion, err = version(doc.get("compatibility-version"), "compatibility-version"); err != nil {
		return nil, err
	}

	// swift-version in v1 and v2 became swift-abi-version in v3, and the
	// values changed meaning with it. Only the ABI version matters to a link,
	// and only as a compatibility check, so both spellings are read into one
	// field and the version number distinguishes them if a caller cares.
	if n := doc.getAny("swift-abi-version", "swift-version"); n != nil {
		fmt.Sscanf(n.text(), "%d", &s.SwiftABI)
	}

	for _, f := range doc.get("flags").list() {
		switch f {
		case "flat_namespace":
			s.Flags |= FlatNamespace
		case "not_app_extension_safe":
			s.Flags |= NotAppExtensionSafe
		case "installapi":
			s.Flags |= InstallAPI
		}
	}

	if err := decodeTargets(s, doc); err != nil {
		return nil, err
	}
	decodeUUIDs(s, doc)
	decodeUmbrella(s, doc)

	// The export section's key set differs by version in two ways this has to
	// account for: v4 renamed weak-def-symbols to weak-symbols, and v4 moved
	// re-exported libraries and allowable clients out of the sections and up
	// to the document.
	if s.exports, err = decodeSections(s, doc.get("exports")); err != nil {
		return nil, err
	}
	// v4 spells the document-level group of re-exported symbols "reexports";
	// the hyphenated spelling is pre-v4, where at this level it does not
	// appear at all. Reading only the hyphenated one silently loses every
	// symbol a v4 stub re-exports — on macOS that is _memcpy, _memset and
	// _bcmp, which libsystem_c re-exports from the platform library rather
	// than defining, so the C library links but memcpy does not.
	if s.reexports, err = decodeSections(s, doc.getAny("reexports", "re-exports")); err != nil {
		return nil, err
	}
	if s.undefineds, err = decodeSections(s, doc.get("undefineds")); err != nil {
		return nil, err
	}

	decodeLibs(s, doc)
	decodeClients(s, doc)
	return s, nil
}

func decodeTargets(s *Stub, doc *node) error {
	if s.Version >= 4 {
		toks := doc.get("targets").list()
		if len(toks) == 0 {
			return fmt.Errorf("%w: no targets", ErrMalformed)
		}
		for _, t := range toks {
			s.Targets = append(s.Targets, parseTargetToken(t))
		}
		return nil
	}
	archs := doc.get("archs").list()
	if len(archs) == 0 {
		return fmt.Errorf("%w: no archs", ErrMalformed)
	}
	raw := doc.get("platform").text()
	s.Targets = crossTargets(archs, parsePlatform(raw), raw)
	return nil
}

// decodeUUIDs reads whichever of the three uuid spellings the file uses.
//
// v2 and v3 write a flow sequence whose items are "arch: uuid" strings; v4
// writes a block sequence of two-key mappings. None of it affects a link, so
// an entry that does not fit either shape is skipped.
func decodeUUIDs(s *Stub, doc *node) {
	n := doc.get("uuids")
	if n == nil {
		return
	}
	for _, it := range n.items() {
		switch it.kind {
		case kindScalar:
			if k, v, ok := splitKey(it.str); ok {
				s.UUIDs[k] = v
			}
		case kindMap:
			if t := it.get("target").text(); t != "" {
				s.UUIDs[t] = it.get("value").text()
			}
		}
	}
}

// decodeUmbrella reads the parent umbrella, which is a plain scalar before v4
// and a per-target list in v4.
func decodeUmbrella(s *Stub, doc *node) {
	n := doc.get("parent-umbrella")
	if n == nil {
		return
	}
	if n.kind == kindScalar {
		s.ParentUmbrella = n.str
		return
	}
	for _, it := range n.items() {
		if u := it.get("umbrella").text(); u != "" {
			s.ParentUmbrella = u
			return
		}
	}
}

func decodeSections(s *Stub, n *node) ([]section, error) {
	var out []section
	for _, it := range n.items() {
		if it.kind != kindMap {
			return nil, fmt.Errorf("%w: line %d: export section is not a mapping",
				ErrMalformed, it.line)
		}
		sec := section{
			targets:     sectionTargets(s, it),
			symbols:     it.get("symbols").list(),
			threadLocal: it.get("thread-local-symbols").list(),
			objcClasses: it.get("objc-classes").list(),
			objcEHTypes: it.get("objc-eh-types").list(),
			objcIvars:   it.get("objc-ivars").list(),
			// v4 calls it weak-symbols; before that an export section used
			// weak-def-symbols and an undefined section weak-ref-symbols. The
			// three never collide, so reading all of them is unambiguous.
			weak: it.getAny("weak-symbols", "weak-def-symbols", "weak-ref-symbols").list(),
		}
		out = append(out, sec)

		// Pre-v4, re-exported libraries and allowable clients live inside the
		// section rather than at the document level. Normalizing them upward
		// means Reexports and Clients read the same for every version.
		if s.Version < 4 {
			if libs := it.get("re-exports").list(); len(libs) > 0 {
				s.libs = append(s.libs, libGroup{targets: sec.targets, libs: libs})
			}
			if cl := it.getAny("allowable-clients", "allowed-clients").list(); len(cl) > 0 {
				s.clients = append(s.clients, clientGroup{targets: sec.targets, clients: cl})
			}
		}
	}
	return out, nil
}

// sectionTargets resolves a section's target list.
//
// A section that names no targets covers every target the document declares,
// which is how a single-architecture stub omits the key entirely.
func sectionTargets(s *Stub, sec *node) []Target {
	if s.Version >= 4 {
		toks := sec.get("targets").list()
		if len(toks) == 0 {
			return s.Targets
		}
		out := make([]Target, 0, len(toks))
		for _, t := range toks {
			out = append(out, parseTargetToken(t))
		}
		return out
	}
	archs := sec.get("archs").list()
	if len(archs) == 0 {
		return s.Targets
	}
	raw := ""
	if len(s.Targets) > 0 {
		raw = s.Targets[0].PlatformRaw
	}
	return crossTargets(archs, platformOf(s), raw)
}

func platformOf(s *Stub) macho.Platform {
	if len(s.Targets) > 0 {
		return s.Targets[0].Platform
	}
	return macho.PlatformUnknown
}

func decodeLibs(s *Stub, doc *node) {
	if s.Version < 4 {
		return
	}
	for _, it := range doc.get("reexported-libraries").items() {
		s.libs = append(s.libs, libGroup{
			targets: sectionTargets(s, it),
			// The spec's own example spells this key both ways in different
			// places — "library" in one and "libraries" in another — and files
			// in the wild use "libraries". Both are read.
			libs: it.getAny("libraries", "library").list(),
		})
	}
}

func decodeClients(s *Stub, doc *node) {
	if s.Version < 4 {
		return
	}
	for _, it := range doc.get("allowable-clients").items() {
		s.clients = append(s.clients, clientGroup{
			targets: sectionTargets(s, it),
			clients: it.get("clients").list(),
		})
	}
}

// version parses a version scalar, defaulting to 1.0 when the key is absent.
func version(n *node, key string) (macho.Version, error) {
	s := n.text()
	if s == "" {
		return macho.MakeVersion(1, 0, 0), nil
	}
	v, err := macho.ParseVersion(s)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %v", ErrMalformed, key, err)
	}
	return v, nil
}

// Supports reports whether the stub covers the given link target.
func (s *Stub) Supports(t macho.Target) bool {
	_, ok := s.resolve(t)
	return ok
}

// resolve picks the target this document actually serves for a link target,
// and reports whether it serves one at all.
//
// An exact match on both CPU and sub-CPU wins, and is the whole story for a
// stub that lists the architecture being linked. What makes this more than an
// identity function is the SDK: since the arm64e transition Apple ships
// libraries whose stubs name only arm64e-macos — libsystem_c.tbd, and so
// every symbol in the C library — while ordinary Apple Silicon programs are
// arm64. Requiring an exact sub-CPU there leaves _printf undefined against
// the SDK every Mac has, so a document with no exact target falls back to one
// that agrees on CPU and platform.
//
// The fallback is deliberately per-document and not per-section: the chosen
// sub-CPU is then held fixed while the export sections are filtered, so a
// stub that does list both arm64 and arm64e still answers an arm64 link with
// the arm64 sections alone. Taking the union across sub-CPUs instead would
// hand out symbols that only the other slice defines.
func (s *Stub) resolve(t macho.Target) (macho.Target, bool) {
	for _, st := range s.Targets {
		if st.Matches(t) {
			return t, true
		}
	}
	for _, st := range s.Targets {
		if st.MatchesArch(t) {
			t.SubCPU = st.SubCPU
			return t, true
		}
	}
	return t, false
}

// ArchNames returns every target the stub declares, in file order. It is what
// a diagnostic prints when Supports says no.
func (s *Stub) ArchNames() []string {
	out := make([]string, 0, len(s.Targets))
	for _, t := range s.Targets {
		out = append(out, t.String())
	}
	return out
}

// Find returns the document with the given install name, searching this stub
// and its inlined documents. It is how a re-export is followed without
// reopening a file.
func (s *Stub) Find(installName string) *Stub {
	if s.InstallName == installName {
		return s
	}
	for _, in := range s.Inlined {
		if in.InstallName == installName {
			return in
		}
	}
	return nil
}