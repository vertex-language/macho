// Package image is the output model: the linked side of the tree.
//
// An Image owns segments, output sections, the symbol table, and the output
// buffer. It does not lay itself out — link does that — but it is what makes an
// illegal layout hard to express and, at Freeze, what checks the ones that
// remain.
//
// # Phases
//
// An Image moves through open -> sealed -> frozen and never backwards.
//
//	open    Segments, sections, and atoms are added. No address exists yet, and
//	        reading one is a phase error rather than a zero.
//	sealed  The set of sections and atoms is final, and the LC_CODE_SIGNATURE
//	        slot is reserved. Addresses and file offsets are assigned in this
//	        phase, repeatedly: the size of the load-command block feeds back
//	        into address assignment, so link iterates until it converges.
//	frozen  Every size and offset is final and the output buffer exists.
//	        Content may be written; nothing may be resized.
//
// The phases exist because the three kinds of mistake they prevent all produce
// a file that parses. Reading an address before assignment yields zero, which
// looks like a legitimate address. Growing a section after layout silently
// overlaps the next one. Writing outside the buffer either panics in a decode
// loop far from the cause or corrupts a neighbour. Each is caught here, at the
// point of the mistake.
package image

import (
	"errors"
	"fmt"

	"github.com/vertex-language/macho"
)

var (
	// ErrNotFrozen means the output buffer was touched before Freeze. There is
	// no buffer before then, because its size is not known.
	ErrNotFrozen = errors.New("image: output buffer touched before Freeze")

	// ErrNoSize means an address or size was read before it was assigned.
	// Returning the zero value instead would be indistinguishable from a
	// legitimately zero address — which __PAGEZERO and every MH_OBJECT section
	// actually have.
	ErrNoSize = errors.New("image: address or size read before assignment")

	// ErrOutOfBounds means a write fell outside the output buffer.
	ErrOutOfBounds = errors.New("image: write outside the output buffer")

	// ErrPhase means an operation was attempted in the wrong phase.
	ErrPhase = errors.New("image: operation out of phase order")

	// ErrLayout means Freeze found a layout that cannot be expressed: an
	// overlap, a zerofill section that is not last in its segment, or a
	// section whose address does not satisfy its own alignment.
	ErrLayout = errors.New("image: inconsistent layout")
)

// Phase is an Image's position in the open -> sealed -> frozen sequence.
type Phase uint8

const (
	PhaseOpen Phase = iota
	PhaseSealed
	PhaseFrozen
)

func (p Phase) String() string {
	switch p {
	case PhaseOpen:
		return "open"
	case PhaseSealed:
		return "sealed"
	case PhaseFrozen:
		return "frozen"
	}
	return "phase(?)"
}

// Options are the layout knobs an Image needs.
//
// This is deliberately a small subset of link.Options. link owns configuration;
// image owns only what changes where a byte lands.
type Options struct {
	// FileType is the output kind. It decides whether there is a __PAGEZERO
	// and which linker-defined header symbol is created.
	FileType macho.FileType

	Flags macho.Flags

	// PageSize is the segment alignment. Zero means the target's natural page
	// size: 16 KiB on every arm64 variant, 4 KiB on x86_64.
	PageSize uint64

	// PageZeroSize is the size of the unmapped region at address zero. Zero
	// means the default for the target's width — 4 GiB for 64-bit, one page
	// for 32-bit — and an explicit zero is spelled by setting NoPageZero.
	//
	// The whole point of the segment is to make a null dereference fault, and
	// 4 GiB rather than one page is what makes a null pointer plus a large
	// 32-bit offset still fault.
	PageZeroSize uint64

	// NoPageZero suppresses __PAGEZERO entirely. A dylib or bundle is loaded
	// into a process that already has one, so it must not declare its own.
	NoPageZero bool
}

// Image is a Mach-O image under construction.
type Image struct {
	target macho.Target
	opts   Options

	phase Phase

	segments  []*Segment
	segByName map[string]*Segment

	sections  []*Section
	secByKey  map[SectionKey]*Section

	syms   *SymbolTable
	inputs []*Input

	synthetics []Synthetic
	finalizers []Finalizer

	reserved []*Sym

	// sigOff and sigSize bound the code signature's reserved slot at the very
	// end of __LINKEDIT.
	sigOff, sigSize uint64
	sigReserved     bool

	// headerSize is the size of the Mach-O header plus the load-command block.
	// link sets it each round of the layout fixpoint, and it is the reason the
	// fixpoint exists: __TEXT starts at file offset 0 and contains it.
	headerSize uint64

	size uint64
	buf  []byte
}

// New returns an open Image for the given target.
func New(t macho.Target) *Image {
	img := &Image{
		target:    t,
		opts:      Options{FileType: macho.MH_EXECUTE},
		segByName: make(map[string]*Segment),
		secByKey:  make(map[SectionKey]*Section),
	}
	img.syms = newSymbolTable(img)
	return img
}

// Target returns the image's target.
func (img *Image) Target() macho.Target { return img.target }

// Width and Endian are derived from the target, never stored, so an image
// cannot claim a width its CPU does not have.
func (img *Image) Width() macho.Width   { return img.target.Width() }
func (img *Image) Endian() macho.Endian { return img.target.Endian }

// Phase returns the image's current phase.
func (img *Image) Phase() Phase { return img.phase }

// Options returns the layout options.
func (img *Image) Options() Options { return img.opts }

// SetOptions replaces the layout options. Open phase only: every one of them
// changes where a byte lands.
func (img *Image) SetOptions(o Options) error {
	if err := img.require(PhaseOpen, "SetOptions"); err != nil {
		return err
	}
	img.opts = o
	return nil
}

// PageSize returns the segment alignment in effect.
func (img *Image) PageSize() uint64 {
	if img.opts.PageSize != 0 {
		return img.opts.PageSize
	}
	switch img.target.CPU {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32, macho.CPU_TYPE_ARM:
		return 16384
	}
	return 4096
}

// PageZeroSize returns the size of __PAGEZERO, or zero if there is none.
func (img *Image) PageZeroSize() uint64 {
	if img.opts.NoPageZero || !img.hasPageZero() {
		return 0
	}
	if img.opts.PageZeroSize != 0 {
		return img.opts.PageZeroSize
	}
	if img.target.Wide() {
		return 1 << 32
	}
	return img.PageSize()
}

// hasPageZero reports whether this output kind gets a __PAGEZERO.
//
// Only a main executable does. A dylib or bundle is loaded into a process that
// already has one, and declaring a second unmapped region at address zero
// would either fail to map or shadow the host's.
func (img *Image) hasPageZero() bool {
	return img.opts.FileType == macho.MH_EXECUTE
}

// BaseAddress returns the address the Mach-O header sits at.
//
// For an executable this is the end of __PAGEZERO; for anything else it is
// zero and dyld slides the image. It is also the value of every linker-defined
// header symbol, which is why those cannot be bound until this is known.
func (img *Image) BaseAddress() uint64 { return img.PageZeroSize() }

// SetHeaderSize records the size of the header plus load-command block.
//
// link calls this each round of the layout fixpoint. __TEXT begins at file
// offset 0 and covers this block, so its value is an input to address
// assignment and cannot be known before the load commands are sized — which in
// turn depends on how many segments and sections the assignment produced.
func (img *Image) SetHeaderSize(n uint64) error {
	if err := img.require(PhaseSealed, "SetHeaderSize"); err != nil {
		return err
	}
	img.headerSize = n
	return nil
}

// HeaderSize returns the recorded header plus load-command size.
func (img *Image) HeaderSize() uint64 { return img.headerSize }

// Symbols returns the image's symbol table.
func (img *Image) Symbols() *SymbolTable { return img.syms }

// Inputs returns every input that contributed to the image.
func (img *Image) Inputs() []*Input { return img.inputs }

// AddInput records an input file.
func (img *Image) AddInput(in *Input) error {
	if err := img.require(PhaseOpen, "AddInput"); err != nil {
		return err
	}
	in.img = img
	img.inputs = append(img.inputs, in)
	return nil
}

// require reports a phase error unless the image is in the given phase.
func (img *Image) require(p Phase, op string) error {
	if img.phase != p {
		return fmt.Errorf("%w: %s requires the %s phase, image is %s",
			ErrPhase, op, p, img.phase)
	}
	return nil
}

// requireAtLeast reports a phase error unless the image has reached p.
func (img *Image) requireAtLeast(p Phase, op string) error {
	if img.phase < p {
		return fmt.Errorf("%w: %s requires at least the %s phase, image is %s",
			ErrPhase, op, p, img.phase)
	}
	return nil
}

// Seal closes the image to new sections and atoms and reserves the code
// signature slot.
//
// The reservation must happen here rather than at emit time. The CodeDirectory
// hashes the file from offset zero up to the start of the signature, which
// means the hashes cover the Mach-O header and the load commands — including
// the LC_CODE_SIGNATURE command itself. So the command must already exist,
// with zeroed data, before any hash is computed. Adding it afterwards would
// invalidate every hash that had just been taken over the bytes it displaced.
func (img *Image) Seal() error {
	if err := img.require(PhaseOpen, "Seal"); err != nil {
		return err
	}
	img.phase = PhaseSealed
	img.orderSegments()
	img.assignOrdinals()
	img.sigReserved = true
	return nil
}

// CodeSignatureReserved reports whether the signature slot exists.
func (img *Image) CodeSignatureReserved() bool { return img.sigReserved }

// SetCodeSignature records where the signature will live.
//
// The size is an estimate during the layout fixpoint and exact by Freeze. It
// is the last thing in the file: everything before it is hashed, so nothing
// may follow it.
func (img *Image) SetCodeSignature(off, size uint64) error {
	if err := img.require(PhaseSealed, "SetCodeSignature"); err != nil {
		return err
	}
	img.sigOff, img.sigSize = off, size
	return nil
}

// CodeSignature returns the reserved slot's offset and size.
func (img *Image) CodeSignature() (off, size uint64) { return img.sigOff, img.sigSize }

// SetSize records the total file size, which Freeze uses to size the buffer.
func (img *Image) SetSize(n uint64) error {
	if err := img.require(PhaseSealed, "SetSize"); err != nil {
		return err
	}
	img.size = n
	return nil
}

// Size returns the total file size.
func (img *Image) Size() uint64 { return img.size }

// Freeze validates the layout and allocates the output buffer.
//
// Everything checked here is a property that produces a file which parses and
// then misbehaves: sections that overlap, a zerofill section with ordinary
// sections after it in the same segment, a section whose address violates its
// own alignment. None of them is detectable downstream.
func (img *Image) Freeze() error {
	if err := img.require(PhaseSealed, "Freeze"); err != nil {
		return err
	}
	if img.size == 0 {
		return fmt.Errorf("%w: file size was never assigned", ErrNoSize)
	}
	for _, seg := range img.segments {
		if err := seg.validate(); err != nil {
			return err
		}
	}
	if img.sigReserved && img.sigSize != 0 {
		if img.sigOff+img.sigSize != img.size {
			return fmt.Errorf("%w: code signature ends at %d, file is %d bytes; "+
				"nothing may follow the signature",
				ErrLayout, img.sigOff+img.sigSize, img.size)
		}
	}
	img.buf = make([]byte, img.size)
	img.phase = PhaseFrozen
	return nil
}

// WriteAt writes into the output buffer.
func (img *Image) WriteAt(off uint64, p []byte) error {
	if img.phase != PhaseFrozen {
		return fmt.Errorf("%w: image is %s", ErrNotFrozen, img.phase)
	}
	if off > img.size || uint64(len(p)) > img.size-off {
		return fmt.Errorf("%w: %d bytes at %d, buffer is %d",
			ErrOutOfBounds, len(p), off, img.size)
	}
	copy(img.buf[off:], p)
	return nil
}

// Slice returns a writable view of the output buffer.
//
// This is what a relocation site is built from: a backend writes a field in
// place rather than through a copy, so the bytes it patches are the bytes that
// get written out.
func (img *Image) Slice(off, n uint64) ([]byte, error) {
	if img.phase != PhaseFrozen {
		return nil, fmt.Errorf("%w: image is %s", ErrNotFrozen, img.phase)
	}
	if off > img.size || n > img.size-off {
		return nil, fmt.Errorf("%w: %d bytes at %d, buffer is %d",
			ErrOutOfBounds, n, off, img.size)
	}
	return img.buf[off : off+n], nil
}

// Bytes returns the finished image.
func (img *Image) Bytes() ([]byte, error) {
	if img.phase != PhaseFrozen {
		return nil, fmt.Errorf("%w: image is %s", ErrNotFrozen, img.phase)
	}
	return img.buf, nil
}

// Reserved returns the linker-defined symbols.
func (img *Image) Reserved() []*Sym { return img.reserved }

// AddReserved seeds the linker-defined symbols.
//
// These must exist before the dead-strip sweep rather than being appended
// afterwards: they are roots, and a root that appears after the sweep names
// atoms that have already been discarded. They also cannot be given values
// until layout is done, which is why binding is a separate step.
func (img *Image) AddReserved() error {
	if err := img.require(PhaseOpen, "AddReserved"); err != nil {
		return err
	}
	names := []string{dsoHandle}
	if h := headerSymbolName(img.opts.FileType); h != "" {
		names = append(names, h)
	}
	for _, n := range names {
		s := img.syms.Intern(n)
		s.Class = ClassDefined
		s.Reserved = true
		s.Root = true
		img.reserved = append(img.reserved, s)
	}
	return nil
}

// BindReserved gives the linker-defined symbols their final values.
//
// Every one of them is the address of the Mach-O header, which is the base
// address of the image. That is not known until __PAGEZERO is sized and
// __TEXT is placed, so this runs inside the layout fixpoint rather than beside
// AddReserved.
func (img *Image) BindReserved() error {
	if err := img.require(PhaseSealed, "BindReserved"); err != nil {
		return err
	}
	base := img.BaseAddress()
	for _, s := range img.reserved {
		s.Value = base
		s.Bound = true
	}
	return nil
}

// Linker-defined symbol names.
//
// Note the doubled underscore: the C identifier is _mh_execute_header, and
// Mach-O prefixes every C symbol with another underscore. Writing the C
// spelling here produces a symbol nothing can find.
const (
	dsoHandle          = "___dso_handle"
	mhExecuteHeader    = "__mh_execute_header"
	mhDylibHeader      = "__mh_dylib_header"
	mhBundleHeader     = "__mh_bundle_header"
	mhDylinkerHeader   = "__mh_dylinker_header"
	mhPreloadHeader    = "__mh_preload_header"
)

func headerSymbolName(t macho.FileType) string {
	switch t {
	case macho.MH_EXECUTE:
		return mhExecuteHeader
	case macho.MH_DYLIB:
		return mhDylibHeader
	case macho.MH_BUNDLE:
		return mhBundleHeader
	case macho.MH_DYLINKER:
		return mhDylinkerHeader
	case macho.MH_PRELOAD:
		return mhPreloadHeader
	}
	return ""
}