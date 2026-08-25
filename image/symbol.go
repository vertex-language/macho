package image

import (
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
)

// SymClass is what a symbol is, once resolution has run.
type SymClass uint8

const (
	// ClassUndefined is a reference with no definition yet. It is an error at
	// the end of resolution unless the reference is weak or undefined symbols
	// are allowed to bind dynamically.
	ClassUndefined SymClass = iota

	// ClassDefined is defined by an atom in this image.
	ClassDefined

	// ClassAbsolute has a fixed value not tied to any atom.
	ClassAbsolute

	// ClassImport is defined by a dylib or stub input and binds at load time.
	ClassImport

	// ClassCommon is a tentative definition whose size is its value, waiting
	// to be given storage or to lose to a real definition.
	ClassCommon
)

func (c SymClass) String() string {
	switch c {
	case ClassUndefined:
		return "undefined"
	case ClassDefined:
		return "defined"
	case ClassAbsolute:
		return "absolute"
	case ClassImport:
		return "import"
	case ClassCommon:
		return "common"
	}
	return "class(?)"
}

// Sym is one symbol in the linked image.
type Sym struct {
	Name  string
	Class SymClass

	// Atom is the definition, for ClassDefined. Value is the final address,
	// filled in once layout is done; for ClassCommon it is the size instead,
	// and for ClassAbsolute it is the value itself.
	Atom  *Atom
	Value uint64

	// Bound reports whether Value is meaningful. Reading an address before
	// binding would yield zero, which is a legal address in a dylib, so the
	// flag is checked rather than the value compared.
	Bound bool

	// Input is the file that supplied the definition, or the library the
	// symbol imports from.
	Input *Input

	// Ordinal is the two-level namespace library ordinal for an import. It is
	// part of the symbol's identity: under MH_TWOLEVEL an undefined symbol
	// names the library it is expected from, and two libraries exporting one
	// name are two different symbols.
	Ordinal macho.LibOrdinal

	// WeakDef marks a definition eligible to lose a coalescing election.
	// WeakRef marks a reference that may go unresolved and bind to zero.
	WeakDef bool
	WeakRef bool

	// ThreadLocal marks a symbol whose value is a TLV descriptor rather than
	// an address.
	ThreadLocal bool

	// Private marks a private external: visible during this link and demoted
	// to a local afterwards, unless -keep_private_externs says otherwise.
	Private bool

	// Exported marks a symbol that belongs in the export trie.
	Exported bool

	// Root marks a dead-strip root.
	Root bool

	// Reserved marks a linker-defined symbol. Its value comes from layout
	// rather than from any input, so resolution must not treat it as
	// undefined.
	Reserved bool

	index int
}

func (s *Sym) String() string {
	return fmt.Sprintf("%s [%v]", s.Name, s.Class)
}

// Defined reports whether the symbol has a definition in this image.
func (s *Sym) Defined() bool {
	return s.Class == ClassDefined || s.Class == ClassAbsolute
}

// Index returns the symbol's position in the emitted symbol table.
func (s *Sym) Index() int { return s.index }

// SymbolTable holds every symbol the link knows about.
//
// A name maps to exactly one *Sym for the life of the link, so pointer
// identity is symbol identity and a symbol can be a map key. Resolution
// mutates the Sym in place as definitions are found rather than replacing it,
// which is what lets a reference recorded early stay valid.
type SymbolTable struct {
	img    *Image
	byName map[string]*Sym
	order  []*Sym
}

func newSymbolTable(img *Image) *SymbolTable {
	return &SymbolTable{img: img, byName: make(map[string]*Sym)}
}

// Intern returns the symbol for a name, creating an undefined one if the table
// has none.
//
// Every reference and every definition goes through here, which is what makes
// the one-Sym-per-name invariant hold without anyone having to check it.
func (t *SymbolTable) Intern(name string) *Sym {
	if s, ok := t.byName[name]; ok {
		return s
	}
	s := &Sym{Name: name, Class: ClassUndefined}
	t.byName[name] = s
	t.order = append(t.order, s)
	return s
}

// Find returns the symbol for a name without creating one.
func (t *SymbolTable) Find(name string) *Sym { return t.byName[name] }

// All returns every symbol in interning order.
func (t *SymbolTable) All() []*Sym { return t.order }

// Undefined returns every symbol still lacking a definition.
//
// A weak reference is excluded: it is allowed to go unresolved and binds to
// zero at runtime, which is the whole point of the bit.
func (t *SymbolTable) Undefined() []*Sym {
	var out []*Sym
	for _, s := range t.order {
		if s.Class == ClassUndefined && !s.WeakRef {
			out = append(out, s)
		}
	}
	return out
}

// Imports returns every symbol bound to a library, grouped in ordinal order.
func (t *SymbolTable) Imports() []*Sym {
	var out []*Sym
	for _, s := range t.order {
		if s.Class == ClassImport {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Ordinal != out[j].Ordinal {
			return out[i].Ordinal < out[j].Ordinal
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Exports returns every symbol that belongs in the export trie.
func (t *SymbolTable) Exports() []*Sym {
	var out []*Sym
	for _, s := range t.order {
		if s.Exported && s.Defined() {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Runs partitions the table into the three runs the symbol table must be
// emitted in — local, external defined, undefined — and assigns each symbol
// its index.
//
// These boundaries are what LC_DYSYMTAB's index and count pairs describe, and
// dyld indexes the table by them. A table emitted in a different order than it
// declares binds the wrong symbols with no diagnostic anywhere, which is why
// the indices are assigned here, from the order actually produced, rather than
// computed separately.
func (t *SymbolTable) Runs() (local, extdef, undef []*Sym) {
	for _, s := range t.order {
		// A coalesced or dead-stripped definition contributes nothing to the
		// output and must not appear, or it would name an atom that was never
		// emitted.
		if s.Atom != nil && (s.Atom.Coalesced || !s.Atom.Live) {
			continue
		}
		switch {
		case s.Class == ClassUndefined || s.Class == ClassImport:
			undef = append(undef, s)
		case s.Private && !t.img.opts.Flags.Has(macho.MH_NOUNDEFS):
			// A private external is external for this link and local
			// afterwards; by emit time it has already served its purpose.
			local = append(local, s)
		case s.Exported || s.Class == ClassAbsolute:
			extdef = append(extdef, s)
		default:
			local = append(local, s)
		}
	}
	byName := func(xs []*Sym) {
		sort.SliceStable(xs, func(i, j int) bool { return xs[i].Name < xs[j].Name })
	}
	byName(extdef)
	byName(undef)

	i := 0
	for _, run := range [][]*Sym{local, extdef, undef} {
		for _, s := range run {
			s.index = i
			i++
		}
	}
	return local, extdef, undef
}