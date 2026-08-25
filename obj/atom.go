package obj

import (
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
)

// Atom is one placeable contribution: the span of a section that a single
// symbol delimits.
//
// Under MH_SUBSECTIONS_VIA_SYMBOLS the compiler promises that a section can be
// cut at every symbol boundary without changing the program's meaning, which is
// what makes dead-stripping and -order_file work at function granularity
// instead of section granularity.
type Atom struct {
	Sec    *Section
	Offset uint64 // from the start of the section
	Size   uint64

	// Sym is the symbol that begins the atom, or nil for the leading span of a
	// section whose first bytes precede any symbol. An anonymous head atom is
	// not an error: a compiler-emitted literal or a padding run legitimately
	// has no name.
	Sym *Symbol

	// Aliases are further symbols at exactly the same address. They name the
	// same bytes and live or die together, so they are not separate atoms.
	Aliases []*Symbol

	// Alt are N_ALT_ENTRY symbols strictly inside the atom: alternate entry
	// points that deliberately do not start one of their own.
	Alt []*Symbol
}

// Addr returns the atom's address in the object's address space.
func (a Atom) Addr() uint64 { return a.Sec.Addr + a.Offset }

// Data reads the atom's bytes.
func (a Atom) Data() ([]byte, error) {
	if a.Sec.Zerofill() {
		return nil, nil
	}
	e, ok, err := a.Sec.Open()
	if err != nil || !ok {
		return nil, err
	}
	return e.Read(int64(a.Offset), int64(a.Size))
}

// Name returns the atom's symbol name, or a synthesized one for an anonymous
// atom.
func (a Atom) Name() string {
	if a.Sym != nil {
		return a.Sym.Name
	}
	return fmt.Sprintf("%s+0x%x", a.Sec, a.Offset)
}

// Root reports whether the atom must survive dead-stripping regardless of
// whether anything references it.
//
// Three independent things can pin an atom: the section attribute
// S_ATTR_NO_DEAD_STRIP, the same intent expressed per-symbol as
// N_NO_DEAD_STRIP, and S_ATTR_LIVE_SUPPORT, which means the atom is live if
// what it refers to is live — a backwards dependency the sweep has to treat as
// a root because it cannot be discovered by walking forwards.
func (a Atom) Root() bool {
	attrs := a.Sec.Attrs()
	if attrs.Has(macho.S_ATTR_NO_DEAD_STRIP) || attrs.Has(macho.S_ATTR_LIVE_SUPPORT) {
		return true
	}
	if a.Sym != nil && (a.Sym.NoDeadStrip() || a.Sym.ReferencedDynamically()) {
		return true
	}
	for _, s := range a.Aliases {
		if s.NoDeadStrip() || s.ReferencedDynamically() {
			return true
		}
	}
	return false
}

// Atoms splits the section at symbol boundaries.
//
// When MH_SUBSECTIONS_VIA_SYMBOLS is clear the section is one atom, because
// the compiler has not promised the cuts are safe and making them anyway
// breaks any code that computes an address by adding to a neighbouring symbol.
//
// Three rules shape the split when the flag is set:
//
//   - A symbol marked N_ALT_ENTRY does not begin an atom. It is an alternate
//     entry into the atom it lands in, and is recorded in that atom's Alt.
//   - Symbols at the same address are aliases of one atom, not separate atoms
//     of zero size.
//   - Bytes before the first symbol form an anonymous atom rather than being
//     folded into the one that follows, since folding would make the first
//     symbol's atom start at an address the symbol does not name.
//
// Literal and cstring sections are a separate case this does not handle: their
// natural subdivision is by content — element size for the fixed-width literal
// types, NUL boundaries for __cstring — and they usually carry no symbols at
// all. That split needs to know about deduplication and belongs in link/split.go,
// so here such a section comes back as one atom.
func (s *Section) Atoms() ([]Atom, error) {
	s.atomOnce.Do(func() { s.atoms, s.atomErr = s.readAtoms() })
	return s.atoms, s.atomErr
}

func (s *Section) readAtoms() ([]Atom, error) {
	if s.Size == 0 {
		return nil, nil
	}
	whole := []Atom{{Sec: s, Offset: 0, Size: s.Size}}

	if !s.f.Subsections() {
		return whole, nil
	}

	syms, err := s.f.Symbols()
	if err != nil {
		// A file with no symbol table has no boundaries to cut at. That is not
		// an error — a stripped object is legal — it just means one atom.
		if err == ErrNoSymbolTable {
			return whole, nil
		}
		return nil, err
	}

	// Collect the symbols that define positions in this section. A symbol
	// whose value falls outside the section is a file that disagrees with
	// itself; drop it rather than producing an atom with a negative offset.
	type boundary struct {
		off uint64
		sym *Symbol
	}
	var bs []boundary
	for _, sym := range syms {
		if !sym.Defined() || sym.Sec != s {
			continue
		}
		if sym.Value < s.Addr || sym.Value >= s.Addr+s.Size {
			continue
		}
		bs = append(bs, boundary{off: sym.Value - s.Addr, sym: sym})
	}
	if len(bs) == 0 {
		return whole, nil
	}

	// Sort by offset. The tie-break makes the split deterministic when several
	// symbols share an address: a non-alt-entry symbol must come before an
	// alt-entry one so the atom's owner is chosen first, and after that the
	// original table order decides, so two runs over the same file agree.
	sort.SliceStable(bs, func(i, j int) bool {
		if bs[i].off != bs[j].off {
			return bs[i].off < bs[j].off
		}
		if bs[i].sym.AltEntry() != bs[j].sym.AltEntry() {
			return !bs[i].sym.AltEntry()
		}
		return bs[i].sym.Index < bs[j].sym.Index
	})

	var out []Atom

	// An alt-entry symbol at offset 0 has nothing to attach to, so the leading
	// span exists whenever the first real boundary is past 0.
	first := -1
	for i, b := range bs {
		if !b.sym.AltEntry() {
			first = i
			break
		}
	}
	if first == -1 {
		// Every symbol is an alt entry, which means none of them starts an
		// atom. The section is one atom and they all sit inside it.
		a := whole[0]
		for _, b := range bs {
			a.Alt = append(a.Alt, b.sym)
		}
		return []Atom{a}, nil
	}
	if bs[first].off > 0 {
		out = append(out, Atom{Sec: s, Offset: 0, Size: bs[first].off})
	}

	for i := first; i < len(bs); i++ {
		if bs[i].sym.AltEntry() {
			continue
		}
		a := Atom{Sec: s, Offset: bs[i].off, Sym: bs[i].sym}

		// Absorb everything up to the next atom-starting symbol: aliases at
		// this exact offset and alt entries anywhere inside.
		j := i + 1
		for ; j < len(bs); j++ {
			switch {
			case bs[j].sym.AltEntry():
				a.Alt = append(a.Alt, bs[j].sym)
			case bs[j].off == a.Offset:
				a.Aliases = append(a.Aliases, bs[j].sym)
			default:
				goto done
			}
		}
	done:
		if j < len(bs) {
			a.Size = bs[j].off - a.Offset
		} else {
			a.Size = s.Size - a.Offset
		}
		out = append(out, a)
		i = j - 1
	}

	// The leading anonymous atom is the only one that can carry alt entries it
	// did not absorb above, since alt entries before the first real boundary
	// belong to it.
	if len(out) > 0 && out[0].Sym == nil {
		for _, b := range bs[:first] {
			out[0].Alt = append(out[0].Alt, b.sym)
		}
	}
	return out, nil
}

// Atoms returns every atom in the file, section by section, in section order.
func (f *File) Atoms() ([]Atom, error) {
	var out []Atom
	for _, s := range f.Sections {
		as, err := s.Atoms()
		if err != nil {
			return nil, err
		}
		out = append(out, as...)
	}
	return out, nil
}