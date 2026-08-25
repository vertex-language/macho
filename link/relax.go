package link

import (
	"fmt"

	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
	"github.com/vertex-language/macho/obj"
)

// Linker optimization hints.
//
// A hint names two or three instructions that the compiler emitted as a
// general address materialization and that the linker may collapse once it
// knows where things landed — adrp+add becomes adr+nop when the target is
// within ±1 MiB, adrp+ldr becomes a pc-relative literal load. Both are pure
// wins: fewer bytes in __TEXT and one less dependent instruction on a hot
// path.
//
// Nothing applies them. No backend implements backend.Relaxer, so relax below
// finds none and reports no change, and the fixpoint settles after the thunk
// round. What is written here is the half that belongs to link: reading the
// hints out of the input objects and resolving their addresses to atoms, which
// has to happen before atoms move and cannot be done by a backend, since a
// backend never sees an obj.File.

// relax runs the backend's relaxation pass, if it has one.
//
// It reports whether anything changed, because a rewrite can shorten a
// sequence and move everything after it — which is why this runs inside the
// layout fixpoint rather than after it.
func (l *Linker) relax(img *image.Image) (bool, error) {
	r, ok := backend.AsRelaxer(l.be)
	if !ok {
		return false, nil
	}
	if !l.hintsDone {
		h, err := l.collectHints()
		if err != nil {
			return false, err
		}
		l.hints, l.hintsDone = h, true
	}
	// Reqs is the only channel a Relaxer has, since Relax takes the image and
	// the requirements and nothing else.
	l.reqs.SetHints(l.hints)
	return r.Relax(img, l.reqs)
}

// collectHints reads every input's LC_LINKER_OPTIMIZATION_HINT and resolves
// each instruction address to an atom and an offset within it.
//
// Two rules discard a hint rather than half-applying it:
//
// A hint whose instructions do not all land in one atom is dropped. After
// dead-stripping and ordering the two halves of an adrp/add pair can be
// arbitrarily far apart, or one of them can be gone; rewriting one of a
// sequence produces code that computes the wrong address, so a hint is
// all-or-nothing. In practice the compiler never emits one that spans a symbol
// boundary, so this drops nothing real and costs one comparison.
//
// A hint naming an address no section covers is dropped by obj.File.Sites,
// which already treats that as unusable for the same reason.
func (l *Linker) collectHints() ([]backend.Hint, error) {
	var out []backend.Hint

	for _, in := range l.inputs {
		if in.kind != inputObject || in.split == nil {
			continue
		}
		hints, err := in.obj.OptimizationHints()
		if err != nil {
			return nil, fmt.Errorf("link: %s: %w", in.name, err)
		}
		for _, h := range hints {
			sites, ok := in.obj.Sites(h)
			if !ok {
				continue
			}
			resolved, ok := l.resolveHint(in, sites)
			if !ok {
				continue
			}
			out = append(out, backend.Hint{Kind: uint8(h.Kind), Sites: resolved})
		}
	}
	return out, nil
}

func (l *Linker) resolveHint(in *inputFile, sites []obj.LOHSite) ([]backend.HintSite, bool) {
	out := make([]backend.HintSite, 0, len(sites))
	var owner *image.Atom

	for _, s := range sites {
		atoms := in.split.bySection[s.Sec]
		a, off, err := l.atomAtIndex(atoms, s.Sec, s.Offset)
		if err != nil {
			return nil, false
		}
		if owner == nil {
			owner = a
		} else if a != owner {
			return nil, false
		}
		if !a.Live || a.Coalesced {
			return nil, false
		}
		out = append(out, backend.HintSite{Atom: a, Offset: off})
	}
	return out, len(out) > 0
}