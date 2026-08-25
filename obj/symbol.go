package obj

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
)

// Symbol is one decoded nlist entry.
//
// Type is the whole n_type byte, not the masked N_TYPE bits, because the two
// answer different questions and collapsing them loses the stab case: when
// Stab is true the byte is a value from <mach-o/stab.h> and the N_TYPE mask
// does not apply to it at all.
type Symbol struct {
	Name  string
	Type  macho.SymType
	Sect  uint8 // raw n_sect ordinal; NO_SECT for undefined and absolute
	Desc  macho.SymDesc
	Value uint64

	// Index is the position in the file's symbol table. Relocations name
	// symbols by this index, and the three-run ordering is a property of it.
	Index int

	// Sec is the section n_sect names, resolved. It is nil for undefined,
	// absolute, and out-of-range ordinals.
	Sec *Section
}

// Stab reports whether this is a debugging entry.
func (s *Symbol) Stab() bool { return s.Type.Stab() }

// Ext reports whether the symbol is external.
func (s *Symbol) Ext() bool { return s.Type.Ext() }

// Pext reports whether the symbol is a private external — visible to the
// linker for this link and stripped to a local afterwards, unless
// -keep_private_externs says otherwise.
func (s *Symbol) Pext() bool { return s.Type.Pext() }

// Undefined reports whether the symbol has no definition in this file.
func (s *Symbol) Undefined() bool {
	return !s.Stab() && s.Type.Type() == macho.N_UNDF
}

// Common reports whether the symbol is a common (tentative) definition: an
// undefined external with a nonzero value, where the value is the size.
//
// This is the one place a zero-versus-nonzero n_value changes an entry's
// meaning rather than its address, which is why it gets a predicate instead of
// being left to callers.
func (s *Symbol) Common() bool {
	return s.Undefined() && s.Ext() && s.Value != 0
}

// CommonAlign returns the log2 alignment of a common symbol.
func (s *Symbol) CommonAlign() uint8 { return macho.GetCommAlign(s.Desc) }

// Absolute reports whether the symbol has a fixed value not tied to a section.
func (s *Symbol) Absolute() bool {
	return !s.Stab() && s.Type.Type() == macho.N_ABS
}

// Defined reports whether the symbol is defined in a section of this file.
func (s *Symbol) Defined() bool {
	return !s.Stab() && s.Type.Type() == macho.N_SECT
}

// Indirect reports whether the symbol is an alias whose n_value indexes the
// string table for the target's name rather than being an address.
func (s *Symbol) Indirect() bool {
	return !s.Stab() && s.Type.Type() == macho.N_INDR
}

// WeakDef reports whether a definition is weak — eligible to lose a
// coalescing election against a strong definition of the same name.
//
// The bit is shared with N_REF_TO_WEAK, which means the opposite thing on a
// reference, so the predicate checks that this is a definition first. Reading
// the bit without that check is the classic way to decide a plain undefined
// reference is a weak definition.
func (s *Symbol) WeakDef() bool {
	return s.Defined() && s.Desc.Has(macho.N_WEAK_DEF)
}

// WeakRef reports whether an undefined reference is weak: the link succeeds
// with the symbol unresolved and it binds to zero at runtime.
func (s *Symbol) WeakRef() bool {
	return s.Undefined() && s.Desc.Has(macho.N_WEAK_REF)
}

// RefToWeak reports whether a reference names a weak definition. This is the
// other meaning of the N_WEAK_DEF bit.
func (s *Symbol) RefToWeak() bool {
	return s.Undefined() && s.Desc.Has(macho.N_REF_TO_WEAK)
}

// NoDeadStrip reports whether the symbol's atom is a dead-strip root.
//
// In an MH_OBJECT the 0x0020 bit means exactly this. The same bit is
// N_DESC_DISCARDED in a linked image, where it is dyld-internal and never
// appears on disk — so this predicate is only meaningful here, in the object
// reader, which is why it lives on obj.Symbol rather than on macho.SymDesc.
func (s *Symbol) NoDeadStrip() bool { return s.Desc.Has(macho.N_NO_DEAD_STRIP) }

// AltEntry reports whether the symbol is an alternate entry point into the
// atom that precedes it rather than the start of a new atom.
//
// This is the exception to subsection splitting: under
// MH_SUBSECTIONS_VIA_SYMBOLS every symbol begins an atom except one marked
// .alt_entry, whose code shares the preceding atom's fate under dead-stripping
// and ordering.
func (s *Symbol) AltEntry() bool { return s.Desc.Has(macho.N_ALT_ENTRY) }

// Resolver reports whether the symbol is an ifunc-style resolver function.
func (s *Symbol) Resolver() bool { return s.Desc.Has(macho.N_SYMBOL_RESOLVER) }

// ReferencedDynamically reports whether the symbol must survive stripping
// because something looks it up by name at runtime.
func (s *Symbol) ReferencedDynamically() bool {
	return s.Desc.Has(macho.REFERENCED_DYNAMICALLY)
}

// LibOrdinal returns the two-level-namespace library ordinal.
//
// It is meaningful only on an undefined symbol in a two-level-namespace file.
// It shares the high byte with the common-symbol alignment, but the two are
// never both meaningful: a common symbol is undefined and not two-level bound.
func (s *Symbol) LibOrdinal() macho.LibOrdinal {
	return macho.GetLibraryOrdinal(s.Desc)
}

// RefType returns the REFERENCE_TYPE bits of n_desc.
func (s *Symbol) RefType() macho.SymDesc { return s.Desc.RefType() }

func (s *Symbol) String() string {
	switch {
	case s.Stab():
		return fmt.Sprintf("%s [stab 0x%02x]", s.Name, uint8(s.Type))
	case s.Undefined():
		return s.Name + " [undefined]"
	case s.Sec != nil:
		return fmt.Sprintf("%s [%s+0x%x]", s.Name, s.Sec, s.Value-s.Sec.Addr)
	default:
		return s.Name
	}
}

// Symbols returns the file's symbol table in file order.
//
// The table is decoded once and cached, so the returned pointers are stable
// for the life of the File and may be used as map keys. The slice is shared;
// callers must not reorder it in place, and in particular must not sort it,
// since the three-run order — local, external defined, undefined — is what
// LC_DYSYMTAB's index and count pairs describe.
func (f *File) Symbols() ([]*Symbol, error) {
	f.symOnce.Do(func() { f.syms, f.symErr = f.readSymbols() })
	return f.syms, f.symErr
}

func (f *File) readSymbols() ([]*Symbol, error) {
	if f.symtab == nil {
		return nil, ErrNoSymbolTable
	}
	w := f.Width()
	esz := format.NlistSize(w)

	// Both reads are bounds-checked against the slice, so a crafted symoff or
	// a count that overruns the file fails here rather than producing entries
	// read from whatever follows.
	nlists, err := f.ext.Read(int64(f.symtab.SymOff), int64(f.symtab.NSyms)*int64(esz))
	if err != nil {
		return nil, fmt.Errorf("obj: symbol table: %w", err)
	}
	strs, err := f.ext.Read(int64(f.symtab.StrOff), int64(f.symtab.StrSize))
	if err != nil {
		return nil, fmt.Errorf("obj: string table: %w", err)
	}

	c := binio.NewCursorAt(nlists, f.Endian().Order(), f.sliceBase+int64(f.symtab.SymOff))
	out := make([]*Symbol, 0, f.symtab.NSyms)
	for i := 0; i < int(f.symtab.NSyms); i++ {
		var n format.Nlist
		if err := n.Decode(c, w); err != nil {
			return nil, err
		}
		name, err := stringAt(strs, n.StrX)
		if err != nil {
			return nil, fmt.Errorf("obj: symbol %d: %w", i, err)
		}
		s := &Symbol{
			Name:  name,
			Type:  n.Type,
			Sect:  n.Sect,
			Desc:  n.Desc,
			Value: n.Value,
			Index: i,
		}
		// A stab's n_sect is a section ordinal for some stab types and
		// meaningless for others, so resolving it here would attach a section
		// to entries that have none. Only real symbols get a Sec.
		if !s.Stab() {
			s.Sec = f.SectionAt(n.Sect)
		}
		out = append(out, s)
	}
	return out, c.Err()
}

// stringAt reads a NUL-terminated name out of the string table.
//
// Offset 0 is the empty string by convention and is not an error. An offset
// past the end is: it means the symbol names bytes the table does not contain,
// and guessing an empty name there would silently produce a table of unnamed
// symbols.
func stringAt(strs []byte, off uint32) (string, error) {
	if off == 0 {
		return "", nil
	}
	if int64(off) >= int64(len(strs)) {
		return "", fmt.Errorf("string offset %d past the %d-byte table", off, len(strs))
	}
	rest := strs[off:]
	for i, b := range rest {
		if b == 0 {
			return string(rest[:i]), nil
		}
	}
	return "", fmt.Errorf("string at offset %d is unterminated", off)
}

// SymbolRuns returns the boundaries of the three runs the symbol table is
// sorted into, from LC_DYSYMTAB.
//
// These are not advisory. Everything downstream indexes the table by them, so
// a file whose declared runs disagree with its actual ordering binds the wrong
// symbols — which is why the write side derives them from the order it emits
// rather than the other way round.
func (f *File) SymbolRuns() (local, extdef, undef [2]uint32, ok bool) {
	if f.dysymtab == nil {
		return local, extdef, undef, false
	}
	d := f.dysymtab
	return [2]uint32{d.ILocalSym, d.NLocalSym},
		[2]uint32{d.IExtDefSym, d.NExtDefSym},
		[2]uint32{d.IUndefSym, d.NUndefSym},
		true
}

// IndirectSymbols returns the indirect symbol table: one symbol index per
// entry of every pointer or stub section, in the order the sections' reserved1
// fields index into.
//
// Two values in it are sentinels rather than indices —
// INDIRECT_SYMBOL_LOCAL and INDIRECT_SYMBOL_ABS — so an entry must be tested
// against both before it is used to index Symbols.
func (f *File) IndirectSymbols() ([]uint32, error) {
	f.indOnce.Do(func() { f.indSyms, f.indErr = f.readIndirect() })
	return f.indSyms, f.indErr
}

func (f *File) readIndirect() ([]uint32, error) {
	if f.dysymtab == nil || f.dysymtab.NIndirectSyms == 0 {
		return nil, nil
	}
	const entry = 4
	data, err := f.ext.Read(int64(f.dysymtab.IndirectSymOff),
		int64(f.dysymtab.NIndirectSyms)*entry)
	if err != nil {
		return nil, fmt.Errorf("obj: indirect symbol table: %w", err)
	}
	c := binio.NewCursorAt(data, f.Endian().Order(),
		f.sliceBase+int64(f.dysymtab.IndirectSymOff))
	out := make([]uint32, 0, f.dysymtab.NIndirectSyms)
	for i := uint32(0); i < f.dysymtab.NIndirectSyms; i++ {
		out = append(out, c.U32())
	}
	return out, c.Err()
}