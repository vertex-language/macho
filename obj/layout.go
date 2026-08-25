package obj

import (
	"fmt"
	"math"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
	"github.com/vertex-language/macho/internal/strtab"
)

// Close lays the file out and writes it.
//
// It is idempotent-guarded: a second call returns the first call's result
// without emitting anything again. A deferred Close after an explicit one is
// therefore harmless, which is the usual reason a Close runs twice.
//
// # Why there is no fixpoint here
//
// sizeofcmds depends only on counts — how many sections, tools, and linker
// option strings — and never on an offset. So the sizes are computed, then the
// addresses, then the commands are encoded with final numbers, in one pass.
// The linker cannot do this: __TEXT begins at file offset 0 and covers the
// load commands, so their size is an input to address assignment and has to
// converge. An object has no such feedback edge.
func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if err := w.emit(); err != nil {
		w.fail(err)
	}
	return w.err
}

// layout is the resolved placement of everything in the file.
type layout struct {
	width macho.Width

	secs []*SectionBuilder // in emit order: zerofill last
	syms []*symbol         // in the three-run order
	st   *strtab.Builder

	nLocal, nExtDef, nUndef uint32

	ncmds      uint32
	sizeOfCmds uint64
	optSizes   []uint64 // per linker-option command, including padding

	dataStart uint64 // first section's file offset
	dataEnd   uint64 // one past the last non-zerofill byte
	vmSize    uint64

	relocOff uint64
	diceOff  uint64
	diceSize uint64
	indOff   uint64
	indCount uint32
	symOff   uint64
	strOff   uint64
	strSize  uint64
	total    uint64

	indirect []uint32
}

func (w *Writer) emit() error {
	if w.opts.Build.Zero() {
		return ErrBuildVersionRequired
	}
	if len(w.secs) > macho.MAX_SECT {
		return fmt.Errorf("%w: %d sections", ErrTooManySections, len(w.secs))
	}

	l := &layout{width: w.opts.Target.Width()}
	if err := w.orderSections(l); err != nil {
		return err
	}
	if err := w.orderSymbols(l); err != nil {
		return err
	}
	if err := w.checkRelocs(); err != nil {
		return err
	}
	w.sizeCommands(l)
	if err := w.place(l); err != nil {
		return err
	}
	return w.write(l)
}

// orderSections assigns the emit order and the 1-based n_sect ordinals.
//
// Zerofill sections go last. They have no file bytes, so a zerofill section
// placed between two ordinary ones would leave the file offsets of everything
// after it disagreeing with their addresses by the zerofill size — the segment
// could no longer be described as one contiguous mapping. Relative order is
// otherwise preserved, so the ordinals a caller can predict from creation
// order still hold within each group.
func (w *Writer) orderSections(l *layout) error {
	for _, s := range w.secs {
		if !s.Zerofill() {
			l.secs = append(l.secs, s)
		}
	}
	for _, s := range w.secs {
		if s.Zerofill() {
			l.secs = append(l.secs, s)
		}
	}
	for i, s := range l.secs {
		s.index = i + 1
	}
	return nil
}

// orderSymbols partitions the table into the three runs and assigns indices.
//
// The partition is not a convention: LC_DYSYMTAB's index and count pairs
// describe exactly these boundaries, and dyld and every other consumer index
// into the table by them. A table emitted in a different order than it
// declares binds the wrong symbols, with no diagnostic anywhere.
//
// Order *within* a run is not constrained by the format. Locals stay in
// definition order and the two external runs are sorted by name, which is what
// as and llvm-mc do — it makes the output deterministic, which the archive
// table of contents needs, and it makes a byte diff against the reference
// toolchain possible.
//
// A private external is N_PEXT together with N_EXT, so it lands in the
// external-defined run. It becomes a local only later, when the linker either
// hides it or -keep_private_externs keeps it.
func (w *Writer) orderSymbols(l *layout) error {
	var local, extdef, undef []*symbol

	for _, s := range w.syms {
		d := &s.def
		switch d.Type {
		case macho.N_SECT:
			if d.Section == nil {
				return fmt.Errorf("%w: %s is N_SECT with no section",
					ErrBadSymbol, d.Name)
			}
			if d.Value > d.Section.Len() {
				return fmt.Errorf("%w: %s at offset %d in %s, which is %d bytes",
					ErrBadSymbol, d.Name, d.Value, d.Section.SecName(), d.Section.Len())
			}
		case macho.N_UNDF:
			if d.Section != nil {
				return fmt.Errorf("%w: %s is undefined but names section %s",
					ErrBadSymbol, d.Name, d.Section.SecName())
			}
			if d.Value != 0 && !d.Ext {
				return fmt.Errorf("%w: %s is a common symbol and must be external",
					ErrBadSymbol, d.Name)
			}
		case macho.N_ABS:
			if d.Section != nil {
				return fmt.Errorf("%w: %s is absolute but names section %s",
					ErrBadSymbol, d.Name, d.Section.SecName())
			}
		default:
			return fmt.Errorf("%w: %s has type 0x%x; want N_UNDF, N_ABS, or N_SECT",
				ErrBadSymbol, d.Name, uint8(d.Type))
		}

		switch {
		case !d.Ext:
			local = append(local, s)
		case d.Type == macho.N_UNDF:
			undef = append(undef, s)
		default:
			extdef = append(extdef, s)
		}
	}

	byName := func(xs []*symbol) {
		sort.SliceStable(xs, func(i, j int) bool { return xs[i].def.Name < xs[j].def.Name })
	}
	byName(extdef)
	byName(undef)

	l.syms = append(append(append(l.syms, local...), extdef...), undef...)
	l.nLocal = uint32(len(local))
	l.nExtDef = uint32(len(extdef))
	l.nUndef = uint32(len(undef))
	for i, s := range l.syms {
		s.index = i
	}

	// Build the string table now: the layout needs its size, and tail sharing
	// means no offset can be known until every string is in.
	l.st = strtab.New()
	for _, s := range l.syms {
		s.ref = l.st.Add(s.def.Name)
	}
	l.st.Pad(l.width.Bits() / 8)
	return l.st.Err()
}

// checkRelocs validates every submitted entry before any offset is computed.
func (w *Writer) checkRelocs() error {
	cpu := w.opts.Target.CPU
	for _, s := range w.secs {
		size := s.Len()
		for i, e := range s.relocs {
			r := e.spec

			// A first-half type that arrived through Reloc rather than
			// RelocPair has no partner behind it. The reverse case — a bare
			// UNSIGNED that was meant to be somebody's partner — is not
			// detectable, since an UNSIGNED on its own is an ordinary,
			// correct relocation.
			if e.role == relocSolo && pairsOn(cpu, r.Type) {
				return fmt.Errorf("%w: %s at %s+0x%x",
					ErrUnpairedReloc, relocTypeName(cpu, r.Type), s.SecName(), r.Address)
			}
			if r.Sym.Valid() && r.Sec != nil {
				return fmt.Errorf("%w: entry %d in %s names both a symbol and a section",
					ErrBadRelocation, i, s.SecName())
			}
			if !r.Sym.Valid() && r.Sec == nil {
				return fmt.Errorf("%w: entry %d in %s names neither a symbol nor a section",
					ErrBadRelocation, i, s.SecName())
			}
			if r.Sym.Valid() && r.Sym.w != w {
				return fmt.Errorf("%w: entry %d in %s names a symbol from another writer",
					ErrBadRelocation, i, s.SecName())
			}
			if r.Sec != nil && r.Sec.w != w {
				return fmt.Errorf("%w: entry %d in %s names a section from another writer",
					ErrBadRelocation, i, s.SecName())
			}
			if r.Address > math.MaxInt32 {
				return fmt.Errorf("%w: entry %d in %s at 0x%x does not fit r_address",
					ErrBadRelocation, i, s.SecName(), r.Address)
			}
			// A relocation writes Length bytes at Address, so the field must
			// lie inside the section. An ADDEND is the exception: it carries a
			// value in r_symbolnum and writes nothing, so its length is not a
			// field width.
			if !isAddend(cpu, r.Type) {
				if end := r.Address + uint64(r.Length.Bytes()); end > size {
					return fmt.Errorf("%w: entry %d writes %d bytes at %s+0x%x, past the %d-byte section",
						ErrBadRelocation, i, r.Length.Bytes(), s.SecName(), r.Address, size)
				}
			}
			// Scattered entries exist for architectures whose relocations
			// cannot name the referenced address any other way. None of the
			// targets this tree emits for is one of them, so the encoding is
			// never chosen — but the choice is made from the target, not
			// assumed, so adding i386 or armv7 changes one function.
			if !supportsScattered(cpu) && r.Sec != nil && r.Sym.Valid() {
				return fmt.Errorf("%w: %v has no scattered relocation form",
					ErrBadRelocation, cpu)
			}
		}
	}
	return nil
}

func isAddend(cpu macho.CPU, typ uint8) bool {
	switch cpu {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32:
		return macho.ARM64Reloc(typ) == macho.ARM64_RELOC_ADDEND
	}
	return false
}

// supportsScattered reports whether the target has a scattered relocation
// form at all. Only the 32-bit x86 and ARM architectures do; neither is a
// target this tree emits for.
func supportsScattered(c macho.CPU) bool {
	return c == macho.CPU_TYPE_X86 || c == macho.CPU_TYPE_ARM
}

// sizeCommands computes ncmds and sizeofcmds.
//
// The command order is not fixed by the format — every offset in the file is
// explicit, so a consumer finds the commands by walking, not by position. Only
// the segment's leading position is conventional. This particular order is the
// one a golden test will pin; nothing depends on it.
func (w *Writer) sizeCommands(l *layout) {
	width := l.width
	align := uint64(format.CmdAlign(width))

	// LC_SEGMENT(_64) with its section array.
	l.ncmds++
	l.sizeOfCmds += uint64(format.SegmentCmdSize(width)) +
		uint64(len(l.secs))*uint64(format.SectionSize(width))

	// LC_BUILD_VERSION with its tool list.
	l.ncmds++
	l.sizeOfCmds += uint64(format.BuildVersionSize) +
		uint64(len(w.opts.Tools))*uint64(format.BuildToolVersionSize)

	// LC_SYMTAB and LC_DYSYMTAB are always emitted, even for a file with no
	// symbols: a missing LC_DYSYMTAB makes some tools treat the whole table as
	// local, and an empty one says the same thing unambiguously.
	l.ncmds += 2
	l.sizeOfCmds += uint64(format.SymtabSize) + uint64(format.DysymtabSize)

	for _, opt := range w.linkerOpts {
		n := uint64(format.LinkerOptionCmdSize)
		for _, a := range opt {
			n += uint64(len(a)) + 1 // NUL
		}
		n = alignUp(n, align)
		l.optSizes = append(l.optSizes, n)
		l.ncmds++
		l.sizeOfCmds += n
	}

	if len(w.dice) > 0 {
		l.ncmds++
		l.sizeOfCmds += uint64(format.LinkeditDataSize)
	}
}

// place assigns every address and file offset.
func (w *Writer) place(l *layout) error {
	width := l.width
	ptr := uint64(width.Bits() / 8)

	cmdsEnd := uint64(format.HeaderSize(width)) + l.sizeOfCmds

	// The section data begins at a multiple of the largest section alignment.
	// Addresses start at zero and file offsets are dataStart plus the address,
	// so this one alignment makes every section's file offset satisfy its own
	// alignment — the segment maps contiguously and offset minus address is a
	// constant for the whole file.
	maxAlign := uint64(1)
	for _, s := range l.secs {
		if a := uint64(1) << s.alignLog; a > maxAlign {
			maxAlign = a
		}
	}
	l.dataStart = alignUp(cmdsEnd, maxAlign)

	var addr uint64
	for _, s := range l.secs {
		addr = alignUp(addr, uint64(1)<<s.alignLog)
		s.addr = addr
		if s.Zerofill() {
			s.off = 0
		} else {
			s.off = l.dataStart + addr
			l.dataEnd = s.off + s.Len()
		}
		addr += s.Len()
	}
	l.vmSize = addr
	if l.dataEnd == 0 {
		l.dataEnd = l.dataStart
	}

	// Relocations follow the section data. Entries are two 32-bit words, so
	// four-byte alignment is what they need.
	off := alignUp(l.dataEnd, 4)
	l.relocOff = off
	for _, s := range l.secs {
		if len(s.relocs) == 0 {
			continue
		}
		off += uint64(len(s.relocs)) * format.RelocSize
	}

	if len(w.dice) > 0 {
		off = alignUp(off, 4)
		l.diceOff = off
		l.diceSize = uint64(len(w.dice)) * format.DataInCodeEntrySize
		off += l.diceSize
	}

	if err := w.buildIndirect(l); err != nil {
		return err
	}
	if len(l.indirect) > 0 {
		off = alignUp(off, 4)
		l.indOff = off
		l.indCount = uint32(len(l.indirect))
		off += uint64(len(l.indirect)) * 4
	}

	// nlist_64's value field is eight bytes at offset eight, so the array is
	// pointer-aligned rather than merely word-aligned.
	off = alignUp(off, ptr)
	l.symOff = off
	off += uint64(len(l.syms)) * uint64(format.NlistSize(width))

	l.strOff = off
	l.strSize = uint64(l.st.Size())
	l.total = off + l.strSize

	// Every offset above lands in a uint32 field. The check is on the total
	// because it dominates all of them, and the failure is worth naming: a
	// truncated offset produces a file that parses and points at the wrong
	// bytes.
	if l.total > math.MaxUint32 {
		return fmt.Errorf("%w: file is %d bytes", ErrFileTooLarge, l.total)
	}
	return nil
}

// buildIndirect flattens the per-section indirect entries into the one shared
// table and records each section's index into it, which is reserved1.
func (w *Writer) buildIndirect(l *layout) error {
	for _, s := range l.secs {
		if len(s.indirect) == 0 {
			continue
		}
		for _, e := range s.indirect {
			switch {
			case e.Local:
				l.indirect = append(l.indirect, macho.INDIRECT_SYMBOL_LOCAL)
			case e.Absolute:
				l.indirect = append(l.indirect, macho.INDIRECT_SYMBOL_ABS)
			case e.Sym.Valid():
				if e.Sym.w != w {
					return fmt.Errorf("%w: %s has an indirect entry from another writer",
						ErrBadSection, s.SecName())
				}
				l.indirect = append(l.indirect, uint32(w.syms[e.Sym.i].index))
			default:
				return fmt.Errorf("%w: %s has an empty indirect entry",
					ErrBadSection, s.SecName())
			}
		}
	}
	return nil
}

// write encodes the whole file into one buffer and hands it to the output.
//
// Buffering rather than streaming means the buffer's length is the file offset
// at every point, so each stage can assert it is where the layout pass said it
// would be. That check is the one thing standing between a size computation
// that drifts from the emit pass and a file that otool parses happily and a
// linker rejects — the same bug class internal/format exists to prevent
// between a reader and a writer.
func (w *Writer) write(l *layout) error {
	t := w.opts.Target
	width := l.width
	b := binio.NewBufSize(t.Endian.Order(), int(l.total))

	h := format.MachHeader{
		Magic:      t.Magic(),
		CPU:        t.CPU,
		SubCPU:     t.SubCPU,
		FileType:   macho.MH_OBJECT,
		NCmds:      l.ncmds,
		SizeOfCmds: uint32(l.sizeOfCmds),
		Flags:      w.opts.Flags,
	}
	h.Encode(b)

	w.writeSegmentCmd(b, l)
	w.writeBuildVersion(b, l)
	w.writeSymtabCmds(b, l)
	w.writeLinkerOptions(b, l)
	w.writeDataInCodeCmd(b, l)

	if err := at(b, uint64(format.HeaderSize(width))+l.sizeOfCmds, "end of load commands"); err != nil {
		return err
	}

	// Section contents.
	for _, s := range l.secs {
		if s.Zerofill() || s.Len() == 0 {
			continue
		}
		b.Zero(int(s.off - uint64(b.Len())))
		if err := at(b, s.off, s.SecName().String()); err != nil {
			return err
		}
		b.Raw(s.data)
	}
	b.Zero(int(alignUp(uint64(b.Len()), 4) - uint64(b.Len())))

	if err := at(b, l.relocOff, "relocations"); err != nil {
		return err
	}
	for _, s := range l.secs {
		for _, e := range s.relocs {
			r, err := w.encodeReloc(e.spec)
			if err != nil {
				return err
			}
			r.Encode(b)
		}
	}

	if l.diceSize > 0 {
		b.Zero(int(l.diceOff - uint64(b.Len())))
		if err := at(b, l.diceOff, "data-in-code table"); err != nil {
			return err
		}
		for _, d := range w.dice {
			e := format.DataInCodeEntry{
				Offset: uint32(d.sec.addr + d.offset),
				Length: d.length,
				Kind:   uint16(d.kind),
			}
			e.Encode(b)
		}
	}

	if l.indCount > 0 {
		b.Zero(int(l.indOff - uint64(b.Len())))
		if err := at(b, l.indOff, "indirect symbol table"); err != nil {
			return err
		}
		for _, v := range l.indirect {
			b.U32(v)
		}
	}

	b.Zero(int(l.symOff - uint64(b.Len())))
	if err := at(b, l.symOff, "symbol table"); err != nil {
		return err
	}
	for _, s := range l.syms {
		w.encodeNlist(b, s, width)
	}

	if err := at(b, l.strOff, "string table"); err != nil {
		return err
	}
	b.Raw(l.st.Bytes())

	if err := b.Err(); err != nil {
		return err
	}
	if err := at(b, l.total, "end of file"); err != nil {
		return err
	}
	_, err := w.out.Write(b.Bytes())
	return err
}

func (w *Writer) writeSegmentCmd(b *binio.Buf, l *layout) {
	width := l.width

	// An MH_OBJECT holds every section in one unnamed segment at address zero,
	// with all three protections set. There is nothing to choose here: the
	// segment is a container for the section array, not a mapping request.
	sc := format.SegmentCmd{
		Cmd:      macho.SegmentCmd(width),
		Name:     "",
		VMAddr:   0,
		VMSize:   l.vmSize,
		FileOff:  l.dataStart,
		FileSize: l.dataEnd - l.dataStart,
		MaxProt:  macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE,
		InitProt: macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE,
		NSects:   uint32(len(l.secs)),
	}
	sc.CmdSize = uint32(sc.TotalSize(width))
	sc.Encode(b, width)

	indBase := uint32(0)
	for _, s := range l.secs {
		fs := format.Section{
			Name:    s.hdr.Name,
			Segment: s.hdr.Segment,
			Addr:    s.addr,
			Size:    s.Len(),
			Off:     uint32(s.off),
			Align:   s.alignLog,
		}
		fs.SetFlags(s.hdr.Type, s.hdr.Attrs)
		if len(s.relocs) > 0 {
			fs.Reloff = uint32(l.relocOff + s.relocBase)
			fs.Nreloc = uint32(len(s.relocs))
		}
		if len(s.indirect) > 0 {
			fs.Reserved1 = indBase
			indBase += uint32(len(s.indirect))
		}
		fs.Encode(b, width)
	}
}

func (w *Writer) writeBuildVersion(b *binio.Buf, l *layout) {
	bv := format.BuildVersion{
		Cmd:      macho.LC_BUILD_VERSION,
		Platform: w.opts.Build.Platform,
		MinOS:    w.opts.Build.MinOS,
		SDK:      w.opts.Build.SDK,
		NTools:   uint32(len(w.opts.Tools)),
	}
	bv.CmdSize = uint32(bv.TotalSize())
	bv.Encode(b)
	for _, t := range w.opts.Tools {
		tv := format.BuildToolVersion{Tool: t.Tool, Version: t.Version}
		tv.Encode(b)
	}
}

func (w *Writer) writeSymtabCmds(b *binio.Buf, l *layout) {
	st := format.Symtab{
		Cmd:     macho.LC_SYMTAB,
		CmdSize: format.SymtabSize,
		SymOff:  uint32(l.symOff),
		NSyms:   uint32(len(l.syms)),
		StrOff:  uint32(l.strOff),
		StrSize: uint32(l.strSize),
	}
	st.Encode(b)

	// The three index/count pairs must describe the order the table was
	// actually emitted in, which is why they are derived from the run lengths
	// rather than set independently. The relocation offset fields stay zero:
	// an object's relocations live with their sections, not in a shared table.
	ds := format.Dysymtab{
		Cmd:            macho.LC_DYSYMTAB,
		CmdSize:        format.DysymtabSize,
		ILocalSym:      0,
		NLocalSym:      l.nLocal,
		IExtDefSym:     l.nLocal,
		NExtDefSym:     l.nExtDef,
		IUndefSym:      l.nLocal + l.nExtDef,
		NUndefSym:      l.nUndef,
		IndirectSymOff: uint32(l.indOff),
		NIndirectSyms:  l.indCount,
	}
	ds.Encode(b)
}

func (w *Writer) writeLinkerOptions(b *binio.Buf, l *layout) {
	for i, opt := range w.linkerOpts {
		start := b.Len()
		lo := format.LinkerOptionCmd{
			Cmd:     macho.LC_LINKER_OPTION,
			CmdSize: uint32(l.optSizes[i]),
			Count:   uint32(len(opt)),
		}
		lo.Encode(b)
		for _, a := range opt {
			b.CString(a)
		}
		b.Zero(int(l.optSizes[i]) - (b.Len() - start))
	}
}

func (w *Writer) writeDataInCodeCmd(b *binio.Buf, l *layout) {
	if l.diceSize == 0 {
		return
	}
	ld := format.LinkeditData{
		Cmd:      macho.LC_DATA_IN_CODE,
		CmdSize:  format.LinkeditDataSize,
		DataOff:  uint32(l.diceOff),
		DataSize: uint32(l.diceSize),
	}
	ld.Encode(b)
}

func (w *Writer) encodeReloc(r RelocSpec) (format.Reloc, error) {
	info := macho.RelocInfo{
		Address: int32(r.Address),
		PCRel:   r.PCRel,
		Length:  r.Length,
		Type:    r.Type,
	}
	if r.Sym.Valid() {
		info.Extern = true
		info.SymbolNum = uint32(w.syms[r.Sym.i].index)
	} else {
		// r_symbolnum holds a 1-based section ordinal when r_extern is clear.
		info.SymbolNum = uint32(r.Sec.index)
	}
	if info.SymbolNum > 0x00ffffff {
		return format.Reloc{}, fmt.Errorf("%w: r_symbolnum %d does not fit 24 bits",
			ErrBadRelocation, info.SymbolNum)
	}
	return format.Reloc{RelocInfo: info}, nil
}

func (w *Writer) encodeNlist(b *binio.Buf, s *symbol, width macho.Width) {
	d := &s.def

	typ := d.Type
	if d.Ext {
		typ |= macho.N_EXT
	}
	if d.Pext {
		typ |= macho.N_PEXT
	}

	desc := d.Desc
	if d.WeakDef && d.Type == macho.N_SECT {
		desc |= macho.N_WEAK_DEF
	}
	if d.WeakRef && d.Type == macho.N_UNDF {
		desc |= macho.N_WEAK_REF
	}
	if d.NoDeadStrip {
		desc |= macho.N_NO_DEAD_STRIP
	}
	if d.AltEntry {
		desc |= macho.N_ALT_ENTRY
	}
	if d.Type == macho.N_UNDF && d.Ext && d.Value != 0 {
		desc = macho.SetCommAlign(desc, d.CommonAlign)
	}

	n := format.Nlist{
		StrX:  s.ref.Offset(),
		Type:  typ,
		Sect:  macho.NO_SECT,
		Desc:  desc,
		Value: d.Value,
	}
	if d.Type == macho.N_SECT {
		n.Sect = uint8(d.Section.index)
		// The caller gave an offset within the section; the file wants an
		// address. This is the only place the two are converted, so a caller
		// never has to know where its section landed.
		n.Value = d.Section.addr + d.Value
	}
	n.Encode(b, width)
}

// at reports whether the buffer is where the layout pass said it would be.
func at(b *binio.Buf, want uint64, what string) error {
	if uint64(b.Len()) != want {
		return fmt.Errorf("obj: internal layout error: %s at %d, expected %d",
			what, b.Len(), want)
	}
	return nil
}

func alignUp(v, n uint64) uint64 {
	if n <= 1 {
		return v
	}
	return (v + n - 1) &^ (n - 1)
}