package obj

import (
	"errors"
	"fmt"
	"io"
	"math/bits"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/strtab"
)

// Write-side errors.
var (
	// ErrTooManySections means the file declares more than 255 sections.
	// n_sect is a single byte, so section 256 is indistinguishable from
	// section 0 and every symbol in the file silently rebinds. This is a
	// hard error, never a truncation.
	ErrTooManySections = errors.New("obj: more than 255 sections")

	// ErrFileTooLarge means a file offset did not fit the uint32 field that
	// carries it. Section offsets, relocation offsets, and every __LINKEDIT
	// table offset are 32-bit even in a 64-bit object.
	ErrFileTooLarge = errors.New("obj: file offset exceeds 4 GB")

	// ErrBuildVersionRequired means Options.Build was left at its zero value.
	// A platform-less object makes every downstream linker guess, and Xcode
	// 15's linker warns about exactly that, so this is an error rather than a
	// default.
	ErrBuildVersionRequired = errors.New("obj: Options.Build is required")

	// ErrUnpairedReloc means a relocation that must travel with a partner was
	// submitted through Reloc rather than RelocPair.
	ErrUnpairedReloc = errors.New("obj: paired relocation submitted without its partner")

	// ErrBadRelocation means a relocation could not be encoded: an address
	// outside its section, a field that runs past the end, a symbol from
	// another writer, or a scattered form the target does not support.
	ErrBadRelocation = errors.New("obj: invalid relocation")

	// ErrBadSymbol means a symbol definition was internally inconsistent —
	// most often N_SECT with no section, or a value outside the section it
	// claims.
	ErrBadSymbol = errors.New("obj: invalid symbol definition")
)

// Options configures a Writer.
type Options struct {
	// Target decides CPU, subtype, byte order, and — through CPU — pointer
	// width. There is no separate width field to disagree with it.
	Target macho.Target

	// Flags is the header flags word. MH_SUBSECTIONS_VIA_SYMBOLS is the one
	// that matters for an object: it promises every section can be cut at
	// symbol boundaries, which is what lets the linker dead-strip and reorder
	// at function granularity.
	Flags macho.Flags

	// Build is the LC_BUILD_VERSION payload and is required. Target already
	// carries the same three values, so macho.Target.Build() fills this in
	// for a caller that has one:
	//
	//	opts := obj.Options{Target: t, Build: t.Build()}
	//
	// The duplication is deliberate rather than elided: the command is
	// required and a zero value must fail loudly, and inferring it silently
	// from Target would defeat that.
	Build macho.BuildVersion

	// Tools is the optional build_tool_version list appended to
	// LC_BUILD_VERSION.
	Tools []ToolVersion
}

// Writer builds an MH_OBJECT file.
//
// Errors latch. Nothing before Close returns one, in the same style as
// binio.Buf, so an emit pass can be a straight run of calls with a single
// check at the end. The first failure is remembered and every later call is a
// no-op, so a caller that ignores the intermediate state still gets the
// original cause from Close rather than a cascade.
//
// A Writer is not safe for concurrent use.
type Writer struct {
	out  io.Writer
	opts Options

	secs   []*SectionBuilder
	secSet map[macho.SecName]*SectionBuilder

	syms   []*symbol
	symSet map[string]*symbol

	linkerOpts [][]string
	dice       []diceEntry

	closed bool
	err    error
}

// NewWriter returns a Writer that emits to out when Close is called.
//
// Nothing is written until Close: the layout pass needs every section size,
// every symbol, and every relocation before it can place the first byte, so
// there is nothing useful to stream.
func NewWriter(out io.Writer, opts Options) *Writer {
	w := &Writer{
		out:    out,
		opts:   opts,
		secSet: make(map[macho.SecName]*SectionBuilder),
		symSet: make(map[string]*symbol),
	}
	if !opts.Target.CPU.Supported() {
		w.fail(fmt.Errorf("%w: %v is not a target this tree emits for",
			macho.ErrUnsupportedCPU, opts.Target.CPU))
	}
	if !opts.Target.Endian.Valid() {
		w.fail(fmt.Errorf("%w: target has no byte order", macho.ErrInvalidTarget))
	}
	return w
}

// fail latches err if this is the first failure.
func (w *Writer) fail(err error) {
	if w.err == nil {
		w.err = err
	}
}

// live reports whether the writer will still accept input.
func (w *Writer) live() bool {
	if w.closed {
		w.fail(errors.New("obj: writer used after Close"))
		return false
	}
	return w.err == nil
}

// Err returns the first error the writer hit, or nil. Close reports the same
// value; this is for a caller that wants to bail out early.
func (w *Writer) Err() error { return w.err }

// SectionHeader describes a section to create.
//
// Align is in BYTES and must be a power of two. The wire form is log2, and
// Close does the conversion — a non-power-of-two is rejected rather than
// silently rounded, because rounding changes where every following section
// lands. This is the same convention the read side presents, so a value never
// changes meaning as it crosses this package.
//
// Note that RelocSpec.Length is *not* the same convention: it is
// macho.RelocLength, whose documented meaning is a log2 byte width and whose
// named constants (RelocLong, RelocQuad) are the intended spelling. A field
// with a semantic type keeps its own units; a bare uint32 does not.
type SectionHeader struct {
	Segment string
	Name    string
	Type    macho.SecType
	Attrs   macho.SecAttrs
	Align   uint32
}

// SectionBuilder accumulates one section's contents and relocations.
//
// It is a different type from the read side's Section on purpose. A parsed
// section has a file offset, a resolved address, and immutable bytes; a
// section under construction has none of those and cannot until Close runs.
// Sharing one type would mean half its fields are meaningless at any given
// moment.
type SectionBuilder struct {
	w *Writer

	hdr      SectionHeader
	alignLog uint32

	data   []byte
	zeroed uint64 // zerofill size, set by Grow

	relocs   []relocEntry
	indirect []IndirectRef

	// Assigned by Close.
	index int
	addr  uint64
	off   uint64

	// relocBase is this section's byte offset into the file's one relocation
	// table, measured from layout.relocOff. The table is shared and the
	// entries are grouped by section, so a section header's reloff is the
	// table's start plus this.
	relocBase uint64
}

// relocEntry is one submitted relocation plus its role in a pair.
type relocEntry struct {
	spec RelocSpec
	role relocRole
}

type relocRole uint8

const (
	relocSolo relocRole = iota
	relocFirst
	relocSecond
)

// Section creates a section. Duplicate (segment, section) identities are
// rejected: they are the same section, and Mach-O has no way to express two.
func (w *Writer) Section(hdr SectionHeader) *SectionBuilder {
	if !w.live() {
		return &SectionBuilder{w: w, hdr: hdr}
	}
	name := macho.Sec(hdr.Segment, hdr.Name)
	if !name.Valid() {
		w.fail(fmt.Errorf("%w: %q does not fit a %d-byte name field",
			ErrBadSection, name, macho.SegNameSize))
		return &SectionBuilder{w: w, hdr: hdr}
	}
	if _, dup := w.secSet[name]; dup {
		w.fail(fmt.Errorf("%w: %s declared twice", ErrBadSection, name))
		return &SectionBuilder{w: w, hdr: hdr}
	}

	align := hdr.Align
	if align == 0 {
		align = 1
	}
	if align&(align-1) != 0 {
		w.fail(fmt.Errorf("%w: %s alignment %d is not a power of two",
			ErrBadSection, name, align))
		return &SectionBuilder{w: w, hdr: hdr}
	}
	if align > 1<<maxAlignLog2 {
		w.fail(fmt.Errorf("%w: %s alignment %d exceeds 2^%d",
			ErrBadSection, name, align, maxAlignLog2))
		return &SectionBuilder{w: w, hdr: hdr}
	}

	s := &SectionBuilder{
		w:        w,
		hdr:      hdr,
		alignLog: uint32(bits.TrailingZeros32(align)),
	}
	w.secs = append(w.secs, s)
	w.secSet[name] = s
	return s
}

// SecName returns the section's identity.
func (s *SectionBuilder) SecName() macho.SecName {
	return macho.Sec(s.hdr.Segment, s.hdr.Name)
}

// Zerofill reports whether the section occupies no bytes in the file.
func (s *SectionBuilder) Zerofill() bool { return s.hdr.Type.Zerofill() }

// Len returns the section's current size.
func (s *SectionBuilder) Len() uint64 {
	if s.Zerofill() {
		return s.zeroed
	}
	return uint64(len(s.data))
}

// Write appends bytes to the section. It implements io.Writer.
func (s *SectionBuilder) Write(p []byte) (int, error) {
	if !s.w.live() {
		return 0, s.w.err
	}
	if s.Zerofill() {
		err := fmt.Errorf("%w: %s is a zerofill section and has no file contents",
			ErrBadSection, s.SecName())
		s.w.fail(err)
		return 0, err
	}
	s.data = append(s.data, p...)
	return len(p), nil
}

// Zero appends n zero bytes, for padding inside a section.
func (s *SectionBuilder) Zero(n int) {
	if n <= 0 {
		return
	}
	s.Write(make([]byte, n))
}

// Grow extends a zerofill section by n bytes.
//
// A zerofill section has a size in memory and no bytes on disk, so it is sized
// rather than written. Calling this on a section with file contents is an
// error rather than a silent tail of zeros.
func (s *SectionBuilder) Grow(n uint64) {
	if !s.w.live() {
		return
	}
	if !s.Zerofill() {
		s.w.fail(fmt.Errorf("%w: %s has file contents; write them, do not Grow",
			ErrBadSection, s.SecName()))
		return
	}
	s.zeroed += n
}

// IndirectRef is one entry of the indirect symbol table.
//
// Two of the three forms are sentinels rather than symbol references:
// INDIRECT_SYMBOL_LOCAL marks a slot the linker fills with a local address,
// and INDIRECT_SYMBOL_ABS an absolute one. They occupy the same array as real
// indices, which is why they are a variant of this type rather than a magic
// SymRef value.
type IndirectRef struct {
	Sym      SymRef
	Local    bool
	Absolute bool
}

// SetIndirect gives the section its indirect symbol table entries, one per
// pointer or stub slot. Close writes them out and fills in reserved1 with the
// section's index into the shared table.
func (s *SectionBuilder) SetIndirect(entries []IndirectRef) {
	if !s.w.live() {
		return
	}
	if !s.hdr.Type.Indirect() {
		s.w.fail(fmt.Errorf("%w: %s is %v and has no indirect symbol entries",
			ErrBadSection, s.SecName(), s.hdr.Type))
		return
	}
	s.indirect = append(s.indirect[:0], entries...)
}

// SymbolDef describes a symbol to define or reference.
//
// Type is the masked N_TYPE value — N_UNDF, N_ABS, or N_SECT — not the whole
// n_type byte. The N_EXT and N_PEXT bits come from Ext and Pext, so a caller
// cannot set a linkage bit and a type that contradict each other. The zero
// value is N_UNDF, which is what makes an undefined reference the shortest
// thing to write:
//
//	puts := w.Symbol(obj.SymbolDef{Name: "_puts", Ext: true})
type SymbolDef struct {
	Name    string
	Type    macho.SymType
	Ext     bool
	Pext    bool
	Section *SectionBuilder

	// Value is an offset within Section for N_SECT, the absolute value for
	// N_ABS, and the size in bytes for a common symbol — an external N_UNDF
	// with a nonzero value. Close adds the section's assigned address for
	// N_SECT, so a caller never handles a final address.
	Value uint64

	// CommonAlign is the log2 alignment of a common symbol. It is ignored for
	// every other kind, since it shares the high byte of n_desc with the
	// library ordinal and the two are never both meaningful.
	CommonAlign uint8

	WeakDef     bool
	WeakRef     bool
	NoDeadStrip bool
	AltEntry    bool

	// Desc is merged into the computed n_desc for bits this struct does not
	// name. The named fields win on conflict.
	Desc macho.SymDesc
}

// symbol is a submitted definition plus the state Close assigns.
type symbol struct {
	def   SymbolDef
	seq   int // submission order, which is the local run's order
	index int // final symbol table index
	ref   *strtab.Ref
}

// SymRef is a handle to a symbol.
//
// It is a handle rather than an index because the index does not exist yet:
// Close reorders the table into the three runs the format requires, so a
// relocation submitted now must name a symbol whose position is decided later.
// The zero value is invalid and means "no symbol", which is how a relocation
// against a section rather than a symbol is spelled.
type SymRef struct {
	w *Writer
	i int
}

// Valid reports whether r names a symbol.
func (r SymRef) Valid() bool { return r.w != nil }

// Symbol defines or references a symbol and returns a handle to it.
//
// A name may appear only once. Two entries with one name is not a state the
// format can express usefully — the linker would see a duplicate definition or
// an ambiguous reference — so it is rejected here rather than at link time.
func (w *Writer) Symbol(def SymbolDef) SymRef {
	if !w.live() {
		return SymRef{}
	}
	if def.Name == "" {
		w.fail(fmt.Errorf("%w: symbol with an empty name", ErrBadSymbol))
		return SymRef{}
	}
	if _, dup := w.symSet[def.Name]; dup {
		w.fail(fmt.Errorf("%w: %s defined twice", ErrBadSymbol, def.Name))
		return SymRef{}
	}
	if def.Section != nil && def.Section.w != w {
		w.fail(fmt.Errorf("%w: %s names a section from another writer",
			ErrBadSymbol, def.Name))
		return SymRef{}
	}

	s := &symbol{def: def, seq: len(w.syms)}
	w.syms = append(w.syms, s)
	w.symSet[def.Name] = s
	return SymRef{w: w, i: s.seq}
}

// RelocSpec describes one relocation entry.
//
// Address is an offset from the start of the section the entry belongs to.
// That is what r_address means in an MH_OBJECT; in a linked image it is a
// different quantity, which is one more reason the read and write types here
// do not serve both.
//
// Exactly one of Sym and Sec names the target. A Sym reference sets r_extern
// and stores the symbol's final index; a Sec reference clears it and stores
// the section's 1-based ordinal.
type RelocSpec struct {
	Address uint64
	Sym     SymRef
	Sec     *SectionBuilder
	Type    uint8
	PCRel   bool
	Length  macho.RelocLength
}

// Reloc submits one relocation.
//
// Entries are emitted in submission order and are never sorted — not here and
// not in Close. See the package's design rules: pair adjacency is positional,
// so any reordering silently miscompiles the instructions the pairs apply to.
func (w *Writer) Reloc(s *SectionBuilder, r RelocSpec) {
	if !w.live() {
		return
	}
	if s == nil || s.w != w {
		w.fail(fmt.Errorf("%w: relocation for a section from another writer",
			ErrBadRelocation))
		return
	}
	s.relocs = append(s.relocs, relocEntry{spec: r, role: relocSolo})
}

// RelocPair submits a relocation and its partner together.
//
// A SUBTRACTOR must be followed by its UNSIGNED, and an ARM64_RELOC_ADDEND by
// its BRANCH26, PAGE21, or PAGEOFF12. Neither entry names the other — the only
// thing binding them is that they are adjacent in the array — so the pair is
// submitted through one call and the adjacency invariant cannot be broken from
// outside the package.
//
// Both entries must sit at the same address: they are one logical operation
// applied to one field.
func (w *Writer) RelocPair(s *SectionBuilder, first, second RelocSpec) {
	if !w.live() {
		return
	}
	if s == nil || s.w != w {
		w.fail(fmt.Errorf("%w: relocation for a section from another writer",
			ErrBadRelocation))
		return
	}
	cpu := w.opts.Target.CPU
	if !pairsOn(cpu, first.Type) {
		w.fail(fmt.Errorf("%w: %s does not take a partner",
			ErrBadRelocation, relocTypeName(cpu, first.Type)))
		return
	}
	if !validPartner(cpu, first.Type, second.Type) {
		w.fail(fmt.Errorf("%w: %s cannot be followed by %s",
			ErrBadRelocation,
			relocTypeName(cpu, first.Type), relocTypeName(cpu, second.Type)))
		return
	}
	if first.Address != second.Address {
		w.fail(fmt.Errorf("%w: pair at 0x%x and 0x%x must share one address",
			ErrBadRelocation, first.Address, second.Address))
		return
	}
	s.relocs = append(s.relocs,
		relocEntry{spec: first, role: relocFirst},
		relocEntry{spec: second, role: relocSecond})
}

// pairsOn reports whether a raw r_type is a first-half type on this CPU.
func pairsOn(cpu macho.CPU, typ uint8) bool {
	switch cpu {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32:
		return macho.ARM64Reloc(typ).Pairs()
	case macho.CPU_TYPE_X86_64:
		return macho.X86_64Reloc(typ).Pairs()
	}
	return false
}

func relocTypeName(cpu macho.CPU, typ uint8) string {
	return Reloc{Type: typ}.TypeName(cpu)
}

// validPartner reports whether second may follow first.
func validPartner(cpu macho.CPU, first, second uint8) bool {
	switch cpu {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32:
		switch macho.ARM64Reloc(first) {
		case macho.ARM64_RELOC_SUBTRACTOR:
			return macho.ARM64Reloc(second) == macho.ARM64_RELOC_UNSIGNED
		case macho.ARM64_RELOC_ADDEND:
			switch macho.ARM64Reloc(second) {
			case macho.ARM64_RELOC_BRANCH26, macho.ARM64_RELOC_PAGE21,
				macho.ARM64_RELOC_PAGEOFF12:
				return true
			}
		}
	case macho.CPU_TYPE_X86_64:
		if macho.X86_64Reloc(first) == macho.X86_64_RELOC_SUBTRACTOR {
			return macho.X86_64Reloc(second) == macho.X86_64_RELOC_UNSIGNED
		}
	}
	return false
}

// LinkerOption records one LC_LINKER_OPTION group.
//
// The group is an argv fragment, and the grouping is the information: the two
// elements of ("-framework", "Foundation") are one option, and flattening them
// into a single list loses which name belongs to which flag.
func (w *Writer) LinkerOption(args ...string) {
	if !w.live() {
		return
	}
	if len(args) == 0 {
		return
	}
	for _, a := range args {
		if a == "" {
			w.fail(errors.New("obj: empty string in a linker option group"))
			return
		}
	}
	w.linkerOpts = append(w.linkerOpts, append([]string(nil), args...))
}

// diceEntry is one pending data-in-code range.
type diceEntry struct {
	sec    *SectionBuilder
	offset uint64
	length uint16
	kind   DICEKind
}

// DataInCode marks a run of bytes inside an executable section as data rather
// than instructions — a jump table, most often.
//
// Anything that rewrites instructions must consult this table first, so an
// object that has jump tables and omits it will be miscompiled by a linker
// that relaxes branches.
func (w *Writer) DataInCode(s *SectionBuilder, offset uint64, length uint16, kind DICEKind) {
	if !w.live() {
		return
	}
	if s == nil || s.w != w {
		w.fail(errors.New("obj: data-in-code range for a section from another writer"))
		return
	}
	w.dice = append(w.dice, diceEntry{sec: s, offset: offset, length: length, kind: kind})
}