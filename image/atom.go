package image

import (
	"fmt"

	"github.com/vertex-language/macho"
)

// InputKind classifies where an input came from.
type InputKind uint8

const (
	InputObject InputKind = iota
	InputArchiveMember
	InputDylib
	InputStub
	InputSynthetic
)

// Input is one file that contributed to the image.
//
// A dylib or stub input contributes no atoms — it supplies definitions that
// stay in the library — but it is still an Input, because it owns a library
// ordinal and every undefined symbol bound to it names that ordinal.
type Input struct {
	Name string
	Kind InputKind

	// InstallName is set for dylib and stub inputs, and is what an
	// LC_LOAD_DYLIB command records.
	InstallName string

	// Ordinal is the two-level namespace library ordinal, assigned in the
	// order the load commands will appear. It is part of an undefined symbol's
	// identity rather than something patched on at emit time: under
	// MH_TWOLEVEL, "_malloc from libSystem" and "_malloc from libfoo" are
	// different symbols and must not resolve to each other.
	Ordinal macho.LibOrdinal

	Atoms []*Atom

	img *Image
}

// AtomSource supplies an atom's bytes.
//
// It is an interface so image does not have to know where content comes from:
// a subsection of an object file, a deduplicated literal, a linker-generated
// table, or nothing at all for zerofill. link supplies the object-backed
// implementation; RawSource and ZeroSource here cover the rest.
type AtomSource interface {
	// Size is the atom's size in bytes, known before any content is read —
	// layout needs it long before Freeze allocates a buffer to read into.
	Size() uint64

	// Zerofill reports whether the atom occupies address space and no file
	// bytes. Bytes is never called on one.
	Zerofill() bool

	// Bytes returns the atom's content. It is called once, after Freeze.
	Bytes() ([]byte, error)
}

// Atom is one placeable contribution: the unit of layout, dead-stripping, and
// ordering.
//
// Under MH_SUBSECTIONS_VIA_SYMBOLS a symbol delimits an atom, and both
// -dead_strip and -order_file operate at that granularity, so sections are the
// wrong unit for everything the linker does between reading and emitting.
//
// Atom is deliberately not split into read and write types the way obj.Section
// and obj.SectionBuilder are. That split stops paying for itself here: an atom
// read from an object and an atom the linker generated are placed, relocated,
// swept, and emitted by exactly the same code, and duplicating the type would
// duplicate all of it.
type Atom struct {
	Name string

	Source AtomSource

	// Align is in bytes and must be a power of two.
	Align uint32

	// Sec and Offset are assigned when the atom is placed. Addr is Sec.Addr
	// plus Offset and is derived rather than stored, so the two cannot drift.
	Sec    *Section
	Offset uint64

	// Live reports whether the atom survived -dead_strip. Root marks it as a
	// starting point for the sweep rather than something the sweep discovers.
	Live bool
	Root bool

	// Coalesced reports that this atom lost a weak-definition election during
	// resolve. It is permanent and independent of Live: a coalesced atom can
	// still be referenced, and those references are redirected to the winner
	// rather than the atom being kept.
	Coalesced bool

	// Sym is the symbol that names this atom, if any. An anonymous atom — a
	// literal, a padding run, the bytes before a section's first symbol — has
	// none.
	Sym *Sym

	// Aliases are further symbols at the atom's address. They name the same
	// bytes and live or die together.
	Aliases []*Sym

	Relocs []Reloc

	Input *Input
}

// Size returns the atom's size.
func (a *Atom) Size() uint64 {
	if a.Source == nil {
		return 0
	}
	return a.Source.Size()
}

// Zerofill reports whether the atom has no file bytes.
func (a *Atom) Zerofill() bool { return a.Source != nil && a.Source.Zerofill() }

// Addr returns the atom's final address.
func (a *Atom) Addr() (uint64, error) {
	if a.Sec == nil || !a.Sec.assigned {
		return 0, fmt.Errorf("%w: %s has not been placed", ErrNoSize, a.Name)
	}
	return a.Sec.Addr + a.Offset, nil
}

// FileOffset returns where the atom's bytes land in the output.
func (a *Atom) FileOffset() (uint64, error) {
	if a.Zerofill() {
		return 0, fmt.Errorf("image: %s is zerofill and has no file offset", a.Name)
	}
	if a.Sec == nil || !a.Sec.assigned {
		return 0, fmt.Errorf("%w: %s has not been placed", ErrNoSize, a.Name)
	}
	return a.Sec.Off + a.Offset, nil
}

func (a *Atom) String() string {
	if a.Name != "" {
		return a.Name
	}
	if a.Sec != nil {
		return fmt.Sprintf("%s+0x%x", a.Sec.Key.Name, a.Offset)
	}
	return "<atom>"
}

// Fragment is an AtomSource for a literal: a run of bytes whose identity is
// its content.
//
// Literal sections are deduplicated by value rather than by symbol — two
// translation units that both contain the string "hello" contribute the same
// fragment — which is why the content is held directly rather than referenced
// through a file.
type Fragment struct {
	Data  []byte
	Align uint32

	// Off is where this literal sat in the object section it was cut from.
	//
	// It exists so that a symbol or a relocation pointing into the middle of
	// a literal section can be resolved to the literal that covers it: the
	// section is one run of bytes in the object and many atoms afterwards,
	// and without the offset every one of them claims to start at zero. A
	// cstring section with a label on each string — which is every
	// Objective-C image, where each selector name carries one — resolves
	// nothing past the first.
	//
	// It takes no part in deduplication: a literal's identity is its
	// content, and two copies at different offsets are the same literal.
	Off uint64
}

func (f *Fragment) Size() uint64           { return uint64(len(f.Data)) }
func (f *Fragment) Zerofill() bool         { return false }
func (f *Fragment) Bytes() ([]byte, error) { return f.Data, nil }

// Reloc is one relocation to apply to an atom.
//
// A submitted SUBTRACTOR/UNSIGNED pair collapses into a single Reloc with Sub
// set, because the pair is one logical operation — the difference between two
// addresses — and keeping it as two entries would let one half be applied
// without the other. That is the same invariant obj.RelocPair enforces on the
// write side, expressed in the model rather than in a call convention.
type Reloc struct {
	// Offset is from the start of the atom, not the section. An atom moves
	// during layout and ordering; a section-relative offset would have to be
	// rewritten every time it did.
	Offset uint64

	// Type is the architecture-specific r_type. Its meaning belongs to the
	// backend, which is the only thing that interprets it.
	Type uint8

	Length macho.RelocLength
	PCRel  bool

	// Sym is the referenced symbol, or nil when the reference is directly to
	// an atom — which is what a local reference within one object becomes once
	// its section ordinal has been resolved to the atom it lands in.
	Sym  *Sym
	Atom *Atom

	// Sub is the subtrahend of a difference relocation.
	Sub *Sym

	// Addend is recovered from the instruction stream or from a preceding
	// ARM64_RELOC_ADDEND entry, because Mach-O relocations carry no addend
	// field. Recovering it is a psABI property and belongs to
	// backend.Backend.Addend; by the time a Reloc exists here it has been
	// recovered and stored.
	Addend int64
}

// Target returns the address the relocation refers to.
func (r Reloc) Target() (uint64, error) {
	switch {
	case r.Atom != nil:
		a, err := r.Atom.Addr()
		return a + uint64(r.Addend), err
	case r.Sym != nil:
		if !r.Sym.Bound {
			return 0, fmt.Errorf("%w: %s is unbound", ErrNoSize, r.Sym.Name)
		}
		return r.Sym.Value + uint64(r.Addend), nil
	}
	return 0, fmt.Errorf("image: relocation names neither a symbol nor an atom")
}
