package link

import (
	"github.com/vertex-language/macho/image"
)

// Dead-stripping, at atom granularity.
//
// The sweep is a reachability walk: start from the roots, follow every
// relocation, and keep what is reached. Everything else is discarded.
//
// Granularity is the whole point. Under MH_SUBSECTIONS_VIA_SYMBOLS one symbol
// delimits one atom, so an unreferenced function goes away without taking its
// neighbours with it. A linker that swept at section granularity would keep
// every function in any file that had one live function, which for a typical
// C++ program is most of the program.
//
// # Liveness and coalescing are separate
//
// An atom that lost a weak-definition election is Coalesced, permanently, and
// that is not the same as being dead. A coalesced atom can still be
// referenced — the reference is redirected to the winner — so a sweep that
// treated the two flags as one would either resurrect the loser or drop a
// reference that still needs redirecting. Collapsing them was a real bug class
// in earlier designs of this linker, which is why image.Atom carries both.

// sweep marks the live atoms, or marks everything live when dead-stripping is
// off.
func (l *Linker) sweep(img *image.Image) error {
	if !l.opts.DeadStrip {
		// Without -dead_strip everything survives. The flag still has to be
		// set rather than ignored, because LiveAtoms filters on it and the
		// rest of the pipeline reads only live atoms.
		for _, a := range l.atoms {
			a.Live = true
		}
		return nil
	}

	work := l.roots(img)
	for _, a := range work {
		a.Live = true
	}

	// An explicit worklist rather than recursion. The reference graph of a
	// large program is deep enough to overflow a goroutine stack, and a
	// linker that crashes on a big input is worse than a slow one.
	for len(work) > 0 {
		a := work[len(work)-1]
		work = work[:len(work)-1]

		for _, r := range a.Relocs {
			for _, next := range l.referents(r) {
				if next == nil || next.Live {
					continue
				}
				next.Live = true
				work = append(work, next)
			}
		}
	}
	return nil
}

// roots returns the atoms the sweep starts from.
//
// Four kinds, and the fourth is the one that is easy to miss. The entry point
// and every exported symbol are obvious. Initializers and terminators are
// roots because nothing in the program calls them — the runtime does, through
// a table. And S_ATTR_LIVE_SUPPORT marks an atom that is live if what it
// *refers to* is live, which is a backwards edge the forward walk cannot
// discover; treating those as roots is conservative and keeps them all.
func (l *Linker) roots(img *image.Image) []*image.Atom {
	var out []*image.Atom
	seen := make(map[*image.Atom]bool)

	add := func(a *image.Atom) {
		if a != nil && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}

	// Symbols marked as roots during resolution: exports, the entry point,
	// N_NO_DEAD_STRIP, and REFERENCED_DYNAMICALLY.
	for _, sym := range img.Symbols().All() {
		if sym.Root && sym.Atom != nil {
			add(sym.Atom)
		}
	}
	// Linker-defined symbols are roots too, and they were seeded before the
	// sweep for exactly this reason: a root discovered afterwards names atoms
	// that have already been discarded.
	for _, sym := range img.Reserved() {
		add(sym.Atom)
	}
	// Atom-level roots from section attributes.
	for _, a := range l.atoms {
		if a.Root {
			add(a)
		}
	}
	return out
}

// referents returns the atoms a relocation keeps alive.
//
// A difference relocation has two, and both matter: the value written depends
// on where each end landed, so discarding either produces a wrong number
// rather than a missing symbol.
func (l *Linker) referents(r image.Reloc) []*image.Atom {
	var out []*image.Atom
	if r.Atom != nil {
		out = append(out, r.Atom)
	}
	if r.Sym != nil {
		out = append(out, l.definingAtom(r.Sym))
	}
	if r.Sub != nil {
		out = append(out, l.definingAtom(r.Sub))
	}
	if r.SubAtom != nil {
		out = append(out, r.SubAtom)
	}
	return out
}

// definingAtom returns the atom a symbol resolves to, following a coalescing
// election to the winner.
//
// A reference to a symbol whose atom lost an election must reach the surviving
// definition, not the discarded one. Since resolution already replaced the
// losing definition in the symbol table, Sym.Atom is the winner and this is
// just a field read — but the redirection is the invariant, and stating it
// here is what keeps the sweep correct if that ever changes.
func (l *Linker) definingAtom(sym *image.Sym) *image.Atom {
	if sym == nil || sym.Atom == nil {
		return nil
	}
	if sym.Atom.Coalesced {
		return nil
	}
	return sym.Atom
}