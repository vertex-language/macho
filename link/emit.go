package link

import (
	"crypto/sha256"
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/codesign"
	"github.com/vertex-language/macho/image"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
)

// The header and the load commands.
//
// This is the other half of assign.go's commands function, and the two are the
// one place in the tree where a structure is described twice. assign needs the
// block's size before the block can be built, because __TEXT starts at file
// offset 0 and contains it; emit needs to write the same set. Nothing enforces
// that they agree. The buffer's length is checked against the reserved size at
// the end, which catches a disagreement in total but not a swap of one command
// for another of the same size — that needs a golden diff against otool -l.

func (l *Linker) emit(img *image.Image) error {
	b := binio.NewBuf(img.Endian().Order())
	w := img.Width()

	ncmds, cmdSize := l.commands(img)

	h := format.MachHeader{
		Magic:      l.target.Magic(),
		CPU:        l.target.CPU,
		SubCPU:     l.target.SubCPU,
		FileType:   l.opts.Output.FileType(),
		NCmds:      ncmds,
		SizeOfCmds: uint32(cmdSize),
		Flags:      l.headerFlags(),
	}
	h.Encode(b)

	for _, seg := range img.Segments() {
		l.emitSegment(b, img, seg)
	}
	l.emitStr(b, macho.LC_LOAD_DYLINKER, dyldPath)
	l.emitSymtabCmds(b, img)
	l.emitUUID(b, img)
	l.emitBuildVersion(b)
	l.emitSourceVersion(b)

	switch l.opts.Output {
	case OutputDylib:
		l.emitDylib(b, macho.LC_ID_DYLIB, l.opts.InstallName,
			l.opts.CurrentVersion, l.opts.CompatVersion)
	default:
		if err := l.emitMain(b, img); err != nil {
			return err
		}
	}
	for _, in := range l.libs {
		if l.opts.DeadStripDylibs && !in.used {
			continue
		}
		l.emitDylib(b, macho.LC_LOAD_DYLIB, in.lib.InstallName(),
			in.lib.CurrentVersion(), in.lib.CompatVersion())
	}
	for _, p := range l.opts.RPaths {
		l.emitStr(b, macho.LC_RPATH, p)
	}

	l.emitLinkeditCmd(b, macho.LC_DYLD_CHAINED_FIXUPS, leChainedFixups)
	l.emitLinkeditCmd(b, macho.LC_DYLD_EXPORTS_TRIE, leExportTrie)
	l.emitLinkeditCmd(b, macho.LC_FUNCTION_STARTS, leFunctionStarts)
	l.emitLinkeditCmd(b, macho.LC_DATA_IN_CODE, leDataInCode)
	sigOff, sigSize := img.CodeSignature()
	l.emitRawLinkeditCmd(b, macho.LC_CODE_SIGNATURE, uint32(sigOff), uint32(sigSize))

	if err := b.Err(); err != nil {
		return err
	}
	if got := uint64(b.Len()); got != uint64(format.HeaderSize(w))+cmdSize {
		return fmt.Errorf("link: emitted %d bytes of header and load commands, layout reserved %d",
			got, uint64(format.HeaderSize(w))+cmdSize)
	}
	if err := img.WriteAt(0, b.Bytes()); err != nil {
		return err
	}

	// Registered after the chain finalizer, which fixups added, and in this
	// order: the UUID is computed over the finished image, and the signature
	// hashes everything including the UUID.
	if err := img.AddFinalizer(&uuidFinalizer{l: l}); err != nil {
		return err
	}
	return img.AddFinalizer(&signFinalizer{l: l})
}

// finalize runs the registered finalizers: chains, then UUID, then signature.
func (l *Linker) finalize(img *image.Image) error { return image.Finalize(img) }

// Indices into linkeditPlan.tables(), so a command's dataoff comes from the
// same place the table was placed.
const (
	leChainedFixups = iota
	leExportTrie
	leFunctionStarts
	leDataInCode
	leSymtab
	leIndirect
	leStrtab
)

func (l *Linker) emitSegment(b *binio.Buf, img *image.Image, seg *image.Segment) {
	w := img.Width()
	sc := format.SegmentCmd{
		Cmd:      macho.SegmentCmd(w),
		Name:     seg.Name,
		VMAddr:   seg.VMAddr,
		VMSize:   seg.VMSize,
		FileOff:  seg.FileOff,
		FileSize: seg.FileSize,
		MaxProt:  seg.MaxProt,
		InitProt: seg.InitProt,
		NSects:   uint32(len(seg.Sections())),
		Flags:    seg.Flags,
	}
	sc.CmdSize = uint32(sc.TotalSize(w))
	sc.Encode(b, w)

	for _, sec := range seg.Sections() {
		r1, r2 := sec.Reserved()
		fs := format.Section{
			Name:      sec.Key.Name.Section,
			Segment:   sec.Key.Name.Segment,
			Addr:      sec.Addr,
			Size:      sec.Size,
			Align:     log2(uint64(sec.Align)),
			Reserved1: r1,
			Reserved2: r2,
		}
		if !sec.Zerofill() {
			fs.Off = uint32(sec.Off)
		}
		fs.SetFlags(sec.Key.Type, sec.Key.Attrs)
		// Relocation offsets stay zero. A linked image carries no relocation
		// array; everything that would have been in one is a chained fixup.
		fs.Encode(b, w)
	}
}

func (l *Linker) emitSymtabCmds(b *binio.Buf, img *image.Image) {
	symOff, symSize := l.le.at(leSymtab)
	strOff, strSize := l.le.at(leStrtab)
	indOff, indSize := l.le.at(leIndirect)

	st := format.Symtab{
		Cmd:     macho.LC_SYMTAB,
		CmdSize: format.SymtabSize,
		SymOff:  uint32(symOff),
		NSyms:   symSize / uint32(format.NlistSize(img.Width())),
		StrOff:  uint32(strOff),
		StrSize: strSize,
	}
	st.Encode(b)

	ds := format.Dysymtab{
		Cmd:            macho.LC_DYSYMTAB,
		CmdSize:        format.DysymtabSize,
		NLocalSym:      l.nLocal,
		IExtDefSym:     l.nLocal,
		NExtDefSym:     l.nExtDef,
		IUndefSym:      l.nLocal + l.nExtDef,
		NUndefSym:      l.nUndef,
		IndirectSymOff: uint32(indOff),
		NIndirectSyms:  indSize / 4,
	}
	ds.Encode(b)
}

func (l *Linker) emitUUID(b *binio.Buf, img *image.Image) {
	// The payload's file offset is recorded so the finalizer can patch it
	// without re-deriving the command's position.
	l.uuidOff = uint64(b.Len()) + 8
	u := format.UUID{Cmd: macho.LC_UUID, CmdSize: format.UUIDSize}
	u.Encode(b)
}

func (l *Linker) emitBuildVersion(b *binio.Buf) {
	bv := format.BuildVersion{
		Cmd:      macho.LC_BUILD_VERSION,
		Platform: l.target.Platform,
		MinOS:    l.target.MinOS,
		SDK:      l.target.SDK,
		NTools:   1,
	}
	bv.CmdSize = uint32(bv.TotalSize())
	bv.Encode(b)
	// LC_VERSION_MIN_* is never written: it cannot express Mac Catalyst, the
	// simulators, DriverKit, or a tool version.
	tv := format.BuildToolVersion{Tool: macho.ToolLD, Version: macho.MakeVersion(1, 0, 0)}
	tv.Encode(b)
}

func (l *Linker) emitSourceVersion(b *binio.Buf) {
	sv := format.SourceVersion{
		Cmd:     macho.LC_SOURCE_VERSION,
		CmdSize: format.SourceVersionSize,
	}
	sv.Encode(b)
}

// emitMain writes LC_MAIN.
//
// EntryOff is a file offset from the start of __TEXT, not a virtual address —
// and since __TEXT begins at file offset 0 and covers the header, the two
// differ by exactly the image base. Writing the address here produces a
// binary that jumps into __PAGEZERO.
func (l *Linker) emitMain(b *binio.Buf, img *image.Image) error {
	sym := img.Symbols().Find(l.opts.Entry)
	if sym == nil || !sym.Bound {
		return fmt.Errorf("%w: %s", ErrNoEntry, l.opts.Entry)
	}
	ep := format.EntryPoint{
		Cmd:      macho.LC_MAIN,
		CmdSize:  format.EntryPointSize,
		EntryOff: sym.Value - img.BaseAddress(),
	}
	ep.Encode(b)
	return nil
}

func (l *Linker) emitDylib(b *binio.Buf, cmd macho.LoadCmd, name string, cur, compat macho.Version) {
	size := padCmd(format.DylibCmdSize+len(name)+1, l.target.Width())
	d := format.DylibCmd{
		Cmd:     cmd,
		CmdSize: uint32(size),
		Dylib: format.Dylib{
			Name:           format.LCStr(format.DylibCmdSize),
			CurrentVersion: cur,
			CompatVersion:  compat,
		},
	}
	start := b.Len()
	d.Encode(b)
	b.CString(name)
	b.Zero(size - (b.Len() - start))
}

func (l *Linker) emitStr(b *binio.Buf, cmd macho.LoadCmd, s string) {
	size := padCmd(format.DylinkerCmdSize+len(s)+1, l.target.Width())
	d := format.DylinkerCmd{Cmd: cmd, CmdSize: uint32(size), Name: format.LCStr(format.DylinkerCmdSize)}
	start := b.Len()
	d.Encode(b)
	b.CString(s)
	b.Zero(size - (b.Len() - start))
}

func (l *Linker) emitLinkeditCmd(b *binio.Buf, cmd macho.LoadCmd, i int) {
	off, size := l.le.at(i)
	l.emitRawLinkeditCmd(b, cmd, uint32(off), size)
}

func (l *Linker) emitRawLinkeditCmd(b *binio.Buf, cmd macho.LoadCmd, off, size uint32) {
	// Emitted even when empty. A zero size says "none" unambiguously; an
	// absent command makes a reader guess whether the information is missing
	// or the linker predates it.
	if size == 0 {
		off = 0
	}
	ld := format.LinkeditData{
		Cmd: cmd, CmdSize: format.LinkeditDataSize, DataOff: off, DataSize: size,
	}
	ld.Encode(b)
}

func padCmd(n int, w macho.Width) int {
	a := format.CmdAlign(w)
	return (n + a - 1) &^ (a - 1)
}

func log2(v uint64) uint32 {
	n := uint32(0)
	for v > 1 {
		v >>= 1
		n++
	}
	return n
}

// uuidFinalizer computes LC_UUID over the finished image.
type uuidFinalizer struct{ l *Linker }

func (u *uuidFinalizer) FinalizerName() string { return "LC_UUID" }

// Finalize hashes the image and writes the result into the reserved payload.
//
// The UUID field is zero while it is hashed, which is what makes the value
// reproducible: hashing a buffer that already contains the answer is not a
// fixpoint anyone wants to run. ld64 uses MD5 here and this uses SHA-256
// truncated to sixteen bytes, so a golden diff against ld64 will differ in
// this one field. Nothing requires the algorithm — dyld wants uniqueness — but
// it does mean the UUID is not a way to check this linker against that one.
func (u *uuidFinalizer) Finalize(img *image.Image) error {
	data, err := img.Bytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	var id [16]byte
	copy(id[:], sum[:16])
	// RFC 4122 version 4 and variant bits, which is what every tool that
	// prints a UUID expects to see even when the value is a hash.
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return img.WriteAt(u.l.uuidOff, id[:])
}

// signFinalizer ad-hoc signs the image.
type signFinalizer struct{ l *Linker }

func (s *signFinalizer) FinalizerName() string { return "code signature" }

// Finalize writes the signature into the slot image reserved during Seal.
//
// It runs last and cannot be folded into emit: the CodeDirectory hashes the
// file from offset zero to the start of the signature, which covers the
// header, every load command including LC_CODE_SIGNATURE itself, and every
// segment. An arm64 macOS binary will not execute without at least this.
func (s *signFinalizer) Finalize(img *image.Image) error {
	if !img.CodeSignatureReserved() {
		return fmt.Errorf("link: no code signature slot was reserved")
	}
	return codesign.SignImage(img, codesign.Options{
		Identifier: s.l.signingIdentifier(),
	})
}