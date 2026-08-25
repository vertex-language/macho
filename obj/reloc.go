package obj

import (
	"errors"
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
)

// Reloc is one decoded relocation entry, of either on-disk form.
//
// The two forms carry different information and this type is the union of
// both, discriminated by Scattered. A scattered entry has no symbol — that is
// why it exists — and carries the referenced address in Value instead.
//
// Type is a uint8 because its meaning is per-architecture. Interpret it with
// macho.ARM64Reloc or macho.X86_64Reloc according to the file's cputype;
// TypeName does that dispatch for diagnostics.
type Reloc struct {
	Address   int64
	Type      uint8
	Length    macho.RelocLength
	PCRel     bool
	Extern    bool
	Scattered bool

	// SymbolNum is a symbol table index when Extern is set, and a 1-based
	// section ordinal when it is not. The field is one field on disk and the
	// meaning flips on a single bit, which is why Sym and Sec below are
	// resolved here rather than left to every caller.
	SymbolNum uint32

	// Value is the referenced address, scattered form only.
	Value int32

	// Sym is set when Extern; Sec is set when a non-scattered entry is not
	// Extern. Exactly one of them is non-nil in a well-formed entry.
	Sym *Symbol
	Sec *Section
}

// Bytes returns the width of the field this relocation writes.
func (r Reloc) Bytes() int { return r.Length.Bytes() }

// TypeName renders r.Type with the right architecture's table.
func (r Reloc) TypeName(cpu macho.CPU) string {
	switch cpu {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32:
		return macho.ARM64Reloc(r.Type).String()
	case macho.CPU_TYPE_X86_64:
		return macho.X86_64Reloc(r.Type).String()
	}
	return fmt.Sprintf("r_type(%d)", r.Type)
}

// Pairs reports whether this entry must be followed by a partner entry.
//
// The partner relationship is positional, not referential: nothing in either
// entry points at the other, so the only thing that binds them is adjacency in
// the array. That is the whole reason the writer never sorts relocations, and
// the reason Relocs below returns them in file order.
func (r Reloc) Pairs(cpu macho.CPU) bool {
	switch cpu {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32:
		return macho.ARM64Reloc(r.Type).Pairs()
	case macho.CPU_TYPE_X86_64:
		return macho.X86_64Reloc(r.Type).Pairs()
	}
	return false
}

// Relocs returns the section's relocation entries in file order.
//
// File order is load-bearing and this function will not change it. A
// SUBTRACTOR is followed by its UNSIGNED and an ARM64_RELOC_ADDEND precedes
// its BRANCH26, PAGE21, or PAGEOFF12, with no field in either entry naming the
// other. Sorting by address — the obvious thing to do, since assemblers
// commonly emit the array in descending address order — separates the halves
// of every pair and silently miscompiles the instructions they apply to.
func (s *Section) Relocs() ([]Reloc, error) {
	s.relocOnce.Do(func() { s.relocs, s.relocErr = s.readRelocs() })
	return s.relocs, s.relocErr
}

func (s *Section) readRelocs() ([]Reloc, error) {
	if s.Nreloc == 0 {
		return nil, nil
	}
	f := s.f

	data, err := f.ext.Read(int64(s.Reloff), int64(s.Nreloc)*format.RelocSize)
	if err != nil {
		return nil, fmt.Errorf("obj: %s relocations: %w", s, err)
	}

	// Extern entries name symbols by index, so the symbol table is needed to
	// resolve them. A file with relocations and no LC_SYMTAB is malformed, but
	// only if an extern entry actually appears — a section relocated entirely
	// against section ordinals needs no table at all.
	syms, symErr := f.Symbols()
	if symErr != nil && !errors.Is(symErr, ErrNoSymbolTable) {
		return nil, symErr
	}

	c := binio.NewCursorAt(data, f.Endian().Order(), f.sliceBase+int64(s.Reloff))
	out := make([]Reloc, 0, s.Nreloc)

	for i := uint32(0); i < s.Nreloc; i++ {
		var any format.AnyReloc
		if err := any.Decode(c); err != nil {
			return nil, err
		}

		var r Reloc
		if any.Scattered {
			r = Reloc{
				Address:   int64(any.Scat.Address),
				Type:      any.Scat.Type,
				Length:    any.Scat.Length,
				PCRel:     any.Scat.PCRel,
				Scattered: true,
				Value:     any.Scat.Value,
			}
			// A scattered entry's r_value is an address, not an index. Attribute
			// it to a section so a caller has somewhere to start; it is a
			// convenience, and Value stays authoritative.
			for _, sec := range f.Sections {
				if sec.Contains(uint64(int64(any.Scat.Value))) {
					r.Sec = sec
					break
				}
			}
		} else {
			n := any.Normal
			r = Reloc{
				Address:   int64(n.Address),
				Type:      n.Type,
				Length:    n.Length,
				PCRel:     n.PCRel,
				Extern:    n.Extern,
				SymbolNum: n.SymbolNum,
			}
			if n.Extern {
				if syms == nil {
					return nil, fmt.Errorf("obj: %s relocation %d names symbol %d: %w",
						s, i, n.SymbolNum, ErrNoSymbolTable)
				}
				if int(n.SymbolNum) >= len(syms) {
					return nil, fmt.Errorf("obj: %s relocation %d names symbol %d of %d",
						s, i, n.SymbolNum, len(syms))
				}
				r.Sym = syms[n.SymbolNum]
			} else {
				// r_symbolnum is a 1-based section ordinal here. Zero is not a
				// legal ordinal in this position, and out-of-range means the
				// entry points at a section the file does not declare.
				r.Sec = f.SectionAt(uint8(n.SymbolNum))
				if r.Sec == nil {
					return nil, fmt.Errorf("obj: %s relocation %d names section ordinal %d of %d",
						s, i, n.SymbolNum, len(f.Sections))
				}
			}
		}
		out = append(out, r)
	}
	return out, c.Err()
}

// RelocPairs walks a relocation array and reports each entry together with its
// partner, if it has one.
//
// It is the read-side check that the adjacency invariant actually holds in an
// input file, and the shape link's relocation application wants: a pair is one
// logical operation and applying either half alone writes a wrong value.
func RelocPairs(cpu macho.CPU, rs []Reloc, fn func(r Reloc, partner *Reloc) error) error {
	for i := 0; i < len(rs); i++ {
		if rs[i].Pairs(cpu) {
			if i+1 >= len(rs) {
				return fmt.Errorf("obj: %s at 0x%x is the last entry and has no partner",
					rs[i].TypeName(cpu), rs[i].Address)
			}
			if err := fn(rs[i], &rs[i+1]); err != nil {
				return err
			}
			i++
			continue
		}
		if err := fn(rs[i], nil); err != nil {
			return err
		}
	}
	return nil
}