package link

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/image"
)

// Merging: literal deduplication and the assignment of atoms to output
// sections.
//
// This is where the flat list of atoms becomes an image. Two things happen,
// and the order matters: literals are deduplicated first, so that the atoms
// placed into output sections are already the surviving copies.
//
// Identical code folding is not implemented. It belongs here, it is a pure
// size optimization, and it needs a correct linker first — see the roadmap.

// merge deduplicates literals and files every live atom into an output
// section.
func (l *Linker) merge(img *image.Image) error {
	if err := l.mergeLiterals(); err != nil {
		return err
	}
	if err := l.placeAtoms(img); err != nil {
		return err
	}
	return l.injectSections(img)
}

// literalKey identifies a literal by its content and the section it belongs
// in.
//
// The section is part of the key because two identical byte sequences in
// different sections are not interchangeable: a pointer-sized literal in
// __literal8 and the same eight bytes in __cstring mean different things, and
// folding them would put one of them in a section whose type describes the
// other.
type literalKey struct {
	sec  macho.SecName
	data string
}

// mergeLiterals folds identical literals into one copy.
//
// # Alignment is the maximum, not the first
//
// A string's required alignment is not recorded anywhere in a Mach-O object.
// clang emits every cstring into one __TEXT,__cstring and expresses individual
// requirements only as .p2align padding, so all that survives into the object
// is the section's alignment — the maximum over everything in it.
//
// That makes deduplication across inputs a hazard rather than a
// simplification. If one object's __cstring is 16-byte aligned because
// something in it is loaded by a SIMD instruction, and another object's copy
// of the same string sits in a 1-byte-aligned section, then folding them onto
// the weaker alignment produces a string the SIMD access faults on. The fault
// happens at runtime, in a program that linked without a diagnostic.
//
// Taking the maximum over every copy is therefore not conservatism, it is the
// only correct choice available given what the format records.
//
// # A literal with a relocation is not a literal
//
// A fragment's identity is its bytes, which is only the whole of it when the
// bytes are the whole of the literal. An S_LITERAL_POINTERS section holds a
// table of *addresses*, and every entry in an object file is eight zero bytes
// plus a relocation — so by content they are all the same literal, and
// folding them collapses the table onto its first entry.
//
// __objc_selrefs is exactly that section. Each entry names one selector, the
// runtime rewrites each in place, and a program whose two selector references
// merged sends the first selector everywhere the second was written: an
// -[NSObject alloc] on an object that was asked for something else entirely.
//
// So an atom carrying relocations is left alone. Its identity is what it
// points at, and that is not known until the addresses are.
func (l *Linker) mergeLiterals() error {
	first := make(map[literalKey]*image.Atom)
	survivors := make([]*image.Atom, 0, len(l.atoms))

	for _, a := range l.atoms {
		frag, ok := a.Source.(*image.Fragment)
		if !ok || !a.Live || len(a.Relocs) > 0 {
			survivors = append(survivors, a)
			continue
		}
		key := literalKey{sec: l.sectionOf(a).Name, data: string(frag.Data)}

		prev, dup := first[key]
		if !dup {
			first[key] = a
			survivors = append(survivors, a)
			continue
		}
		// Fold into the first copy, widening its alignment if this one needed
		// more.
		if a.Align > prev.Align {
			prev.Align = a.Align
			if pf, ok := prev.Source.(*image.Fragment); ok {
				pf.Align = a.Align
			}
		}
		// The folded atom is gone, and every symbol naming it now names the
		// survivor. Marking it Coalesced rather than merely not-Live is
		// deliberate: the two flags mean different things and something may
		// still hold a reference that has to be redirected.
		a.Coalesced = true
		l.redirect(a, prev)
	}

	l.atoms = survivors
	return nil
}

// redirect points every symbol and relocation at a folded atom's survivor.
func (l *Linker) redirect(from, to *image.Atom) {
	if l.folded == nil {
		l.folded = make(map[*image.Atom]*image.Atom)
	}
	l.folded[from] = to
	if from.Sym != nil {
		from.Sym.Atom = to
	}
	for _, a := range l.atoms {
		for i := range a.Relocs {
			if a.Relocs[i].Atom == from {
				a.Relocs[i].Atom = to
			}
		}
	}
}

// placeAtoms files every live atom into its output section.
//
// The section key carries type and attributes as well as the name pair,
// because merging across either is wrong in a way nothing downstream detects:
// folding an S_ZEROFILL section into an S_REGULAR one of the same name would
// give the result file bytes for content that has none, and folding across
// attributes would drop S_ATTR_NO_DEAD_STRIP from half the contributions.
func (l *Linker) placeAtoms(img *image.Image) error {
	for _, a := range l.atoms {
		if !a.Live || a.Coalesced {
			continue
		}
		key := l.sectionOf(a)
		sec, err := img.Section(key)
		if err != nil {
			return err
		}
		if err := sec.AddAtom(a); err != nil {
			return err
		}
	}
	return nil
}

// sectionOf returns the output section key an atom belongs in.
//
// The mapping is almost always identity — an atom from __TEXT,__text goes to
// __TEXT,__text — with two renames the format requires. __compact_unwind is
// consumed by the linker and replaced by __unwind_info, so its atoms never
// reach an output section under their input name. And the __LD segment those
// entries live in exists only in object files.
func (l *Linker) sectionOf(a *image.Atom) image.SectionKey {
	if k, ok := l.atomSection[a]; ok {
		return k
	}
	// An atom whose section was never recorded is linker-generated; put it in
	// __TEXT,__text, which is where a synthetic with no opinion belongs.
	return image.SectionKey{
		Name:  macho.Sec(macho.SEG_TEXT, macho.SECT_TEXT),
		Type:  macho.S_REGULAR,
		Attrs: macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
	}
}

// injectSections creates the sections given with -sectcreate.
//
// The content is one atom with no relocations and no symbol. It is a root:
// nothing in the program references it — that is the point of injecting it —
// so the sweep would otherwise discard it immediately.
func (l *Linker) injectSections(img *image.Image) error {
	for name, data := range l.opts.SectionData {
		key := image.SectionKey{Name: name, Type: macho.S_REGULAR}
		if img.FindSection(key) != nil {
			return fmt.Errorf("link: -sectcreate %s collides with a section from an input", name)
		}
		sec, err := img.Section(key)
		if err != nil {
			return err
		}
		a := &image.Atom{
			Name:   "-sectcreate " + name.String(),
			Source: image.RawSourceOf(data),
			Align:  1,
			Live:   true,
			Root:   true,
		}
		if err := sec.AddAtom(a); err != nil {
			return err
		}
		l.atoms = append(l.atoms, a)
	}
	return nil
}
