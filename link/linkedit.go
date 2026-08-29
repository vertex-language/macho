package link

import (
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
	"github.com/vertex-language/macho/internal/strtab"
	"github.com/vertex-language/macho/internal/trie"
	"github.com/vertex-language/macho/obj"
)

// The __LINKEDIT tables.
//
// Every one of these is derived from state that is already final: the symbol
// table from resolution, the addresses from layout. Nothing here decides
// anything; it encodes. The one thing it must not get wrong is the
// correspondence between the order symbols are emitted in and the index and
// count pairs LC_DYSYMTAB declares, because dyld indexes the table by those
// and a mismatch binds the wrong symbols with no diagnostic anywhere. That is
// why Runs assigns the indices from the order it produces rather than the
// order being derived from the counts.

func (l *Linker) linkedit(img *image.Image) error {
	if err := l.buildSymtab(img); err != nil {
		return err
	}
	if err := l.buildIndirect(img); err != nil {
		return err
	}
	if err := l.buildExports(img); err != nil {
		return err
	}
	if err := l.buildFunctionStarts(img); err != nil {
		return err
	}
	return l.buildDataInCode(img)
}

// buildSymtab encodes the nlist array and the string table.
func (l *Linker) buildSymtab(img *image.Image) error {
	local, extdef, undef := img.Symbols().Runs()
	l.nLocal = uint32(len(local))
	l.nExtDef = uint32(len(extdef))
	l.nUndef = uint32(len(undef))
	l.symIndex = make(map[*image.Sym]int, len(local)+len(extdef)+len(undef))

	st := strtab.New()
	refs := make([]*strtab.Ref, 0, len(local)+len(extdef)+len(undef))
	all := make([]*image.Sym, 0, cap(refs))
	for _, run := range [][]*image.Sym{local, extdef, undef} {
		for _, s := range run {
			all = append(all, s)
			refs = append(refs, st.Add(s.Name))
		}
	}
	st.Pad(l.be.WordSize())
	if err := st.Err(); err != nil {
		return err
	}

	b := binio.NewBuf(img.Endian().Order())
	w := img.Width()
	for i, s := range all {
		l.symIndex[s] = i
		n, err := l.nlistFor(s, refs[i], i < len(local))
		if err != nil {
			return err
		}
		n.Encode(b, w)
	}
	if err := b.Err(); err != nil {
		return err
	}
	l.le.Symtab = b.Bytes()
	l.le.Strtab = st.Bytes()
	return nil
}

// nlistFor encodes one symbol.
//
// isLocal comes from which run the symbol landed in rather than from the
// symbol, because that is the thing the emitted table has to agree with — a
// private extern is external during the link and a local in the output, and
// which side of that line it is on was decided by Runs.
func (l *Linker) nlistFor(s *image.Sym, ref *strtab.Ref, isLocal bool) (format.Nlist, error) {
	n := format.Nlist{StrX: ref.Offset(), Sect: macho.NO_SECT}

	switch s.Class {
	case image.ClassUndefined, image.ClassImport:
		n.Type = macho.N_UNDF | macho.N_EXT
		if s.WeakRef {
			n.Desc |= macho.N_WEAK_REF
		}
		if s.WeakDef {
			n.Desc |= macho.N_REF_TO_WEAK
		}
		if l.opts.Namespace == NamespaceTwoLevel {
			// The ordinal is part of the symbol's identity, not a field
			// patched on here; this only writes down what resolution decided.
			n.Desc = macho.SetLibraryOrdinal(n.Desc, s.Ordinal)
		}

	case image.ClassAbsolute:
		n.Type = macho.N_ABS
		if !isLocal {
			n.Type |= macho.N_EXT
		}
		n.Value = s.Value

	default:
		if s.Atom == nil || s.Atom.Sec == nil {
			return format.Nlist{}, fmt.Errorf("link: %s is defined and unplaced", s.Name)
		}
		n.Type = macho.N_SECT
		switch {
		case !isLocal:
			n.Type |= macho.N_EXT
		case s.Private && l.opts.KeepPrivateExterns:
			n.Type |= macho.N_PEXT | macho.N_EXT
		}
		ord := s.Atom.Sec.Index()
		if ord <= 0 || ord > macho.MAX_SECT {
			return format.Nlist{}, fmt.Errorf("link: %s names section ordinal %d", s.Name, ord)
		}
		n.Sect = uint8(ord)
		n.Value = s.Value
		if s.WeakDef {
			n.Desc |= macho.N_WEAK_DEF
		}
		if s.Root {
			n.Desc |= macho.N_NO_DEAD_STRIP
		}
	}
	return n, nil
}

// buildIndirect encodes the shared indirect symbol table.
//
// The order is fixed in order.go, where each section's reserved1 was set to
// its start in this table: the GOT, then the stubs, then the lazy pointers.
// Building it in any other order here misattributes every slot, and nothing
// downstream can detect that — reserved1 and this array are the only two
// things that describe the correspondence, and they would agree with each
// other while both being wrong.
func (l *Linker) buildIndirect(img *image.Image) error {
	b := binio.NewBuf(img.Endian().Order())

	emit := func(syms []*image.Sym) error {
		for _, s := range syms {
			i, ok := l.symIndex[s]
			if !ok {
				// A slot whose symbol is not in the emitted table cannot be
				// named. INDIRECT_SYMBOL_LOCAL is the sentinel for a slot the
				// linker filled in itself, which is what a stripped local
				// definition amounts to.
				b.U32(macho.INDIRECT_SYMBOL_LOCAL)
				continue
			}
			b.U32(uint32(i))
		}
		return nil
	}

	if err := emit(l.reqs.GOTSyms()); err != nil {
		return err
	}
	if err := emit(l.reqs.StubSyms()); err != nil {
		return err
	}
	if st, ok := backendStubShape(l); ok && st.Kind.Lazy() {
		if err := emit(l.reqs.StubSyms()); err != nil {
			return err
		}
	}
	if err := b.Err(); err != nil {
		return err
	}
	l.le.IndirectSymbols = b.Bytes()
	return nil
}

// buildExports encodes the export trie.
func (l *Linker) buildExports(img *image.Image) error {
	base := img.BaseAddress()
	syms := img.Symbols().Exports()
	if len(syms) == 0 {
		return nil
	}
	out := make([]trie.Export, 0, len(syms))
	for _, s := range syms {
		if !s.Bound {
			return fmt.Errorf("link: %s is exported and unbound", s.Name)
		}
		e := trie.Export{Name: s.Name, Address: s.Value - base}
		switch {
		case s.ThreadLocal:
			e.Flags |= trie.ExportKindTLV
		case s.Class == image.ClassAbsolute:
			e.Flags |= trie.ExportKindAbsolute
			e.Address = s.Value // an absolute export is not header-relative
		}
		if s.WeakDef {
			e.Flags |= trie.ExportWeakDefinition
		}
		out = append(out, e)
	}
	blob, err := trie.Build(out)
	if err != nil {
		return err
	}
	l.le.ExportTrie = blob
	return nil
}

// buildFunctionStarts encodes the compressed function address table.
//
// It is a run of ULEB128 deltas from the previous function, starting at the
// image base, terminated by a zero. Which atoms count as functions is decided
// by the section attribute rather than by the symbol table, which is what lets
// the table cover a stripped binary's functions — that is the whole reason the
// table exists.
func (l *Linker) buildFunctionStarts(img *image.Image) error {
	base := img.BaseAddress()
	var addrs []uint64
	for _, sec := range img.Sections() {
		if !sec.Key.Attrs.Has(macho.S_ATTR_PURE_INSTRUCTIONS) {
			continue
		}
		for _, a := range sec.LiveAtoms() {
			v, err := a.Addr()
			if err != nil {
				return err
			}
			addrs = append(addrs, v)
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

	b := binio.NewBuf(img.Endian().Order())
	prev := base
	for _, a := range addrs {
		if a == prev {
			continue // an alias at the same address is one function
		}
		b.ULEB128(a - prev)
		prev = a
	}
	b.U8(0)
	b.Align(l.be.WordSize())
	if err := b.Err(); err != nil {
		return err
	}
	l.le.FunctionStarts = b.Bytes()
	return nil
}

// buildDataInCode maps every input's data-in-code ranges onto output offsets.
//
// The entries have to be translated rather than concatenated: an input's
// offsets are in its own address space, and the atom they fall in has moved.
// An entry whose range no longer resolves is dropped, because a stale range
// tells a disassembler that instructions are data.
func (l *Linker) buildDataInCode(img *image.Image) error {
	base := img.BaseAddress()
	type entry struct {
		off    uint32
		length uint16
		kind   uint16
	}
	var out []entry

	for _, in := range l.inputs {
		if in.kind != inputObject || in.split == nil {
			continue
		}
		dice, err := in.obj.DataInCode()
		if err != nil {
			return fmt.Errorf("link: %s: %w", in.name, err)
		}
		for _, d := range dice {
			if d.Sec == nil {
				continue
			}
			atoms := in.split.bySection[d.Sec]
			a, off, err := l.atomAtIndex(atoms, d.Sec, uint64(d.Offset)-d.Sec.Addr)
			if err != nil || !a.Live || a.Coalesced {
				continue
			}
			addr, err := a.Addr()
			if err != nil {
				return err
			}
			out = append(out, entry{
				off:    uint32(addr + off - base),
				length: d.Length,
				kind:   uint16(d.Kind),
			})
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].off < out[j].off })

	b := binio.NewBuf(img.Endian().Order())
	for _, e := range out {
		d := format.DataInCodeEntry{Offset: e.off, Length: e.length, Kind: e.kind}
		d.Encode(b)
	}
	if err := b.Err(); err != nil {
		return err
	}
	l.le.DataInCode = b.Bytes()
	return nil
}

// backendStubShape is the discovery helper spelled out once so the three
// callers that need a StubShape do not each write the assertion.
func backendStubShape(l *Linker) (shape backend.StubShape, ok bool) {
	st, ok := backend.AsStubber(l.be)
	if !ok {
		return shape, false
	}
	return st.StubShape(), true
}

var _ = obj.ErrNoSymbolTable // obj is used by buildDataInCode through in.obj