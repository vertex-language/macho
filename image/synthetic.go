package image

import "fmt"

// Synthetic is content the linker generates rather than reads.
//
// Stubs, the GOT, the indirect symbol table, __unwind_info, and the chained
// fixup chains are all synthetic. They are modelled as atoms in ordinary
// sections rather than as a special case in the emitter, so that ordering,
// alignment, and address assignment work on them without knowing they are
// generated — and so that a relocation can point at one.
//
// Generation happens in two steps because of a circularity: a stub's size is
// known before layout, but its content is the address of something that layout
// has not placed yet. Size is therefore answered during the open phase and
// bytes are produced after Freeze.
type Synthetic interface {
	// SyntheticName is used in diagnostics and as the generated atom's name.
	SyntheticName() string

	// Prepare registers the synthetic's atoms with the image. It runs in the
	// open phase, so it may create sections and atoms but may not read any
	// address.
	Prepare(img *Image) error

	// Generate fills in the atoms' content. It runs after Freeze, when every
	// address is final.
	Generate(img *Image) error
}

// AddSynthetic registers a generator.
func (img *Image) AddSynthetic(s Synthetic) error {
	if err := img.require(PhaseOpen, "AddSynthetic"); err != nil {
		return err
	}
	img.synthetics = append(img.synthetics, s)
	return nil
}

// PrepareSynthetics runs every registered generator's Prepare, in registration
// order.
func PrepareSynthetics(img *Image) error {
	if err := img.require(PhaseOpen, "PrepareSynthetics"); err != nil {
		return err
	}
	for _, s := range img.synthetics {
		if err := s.Prepare(img); err != nil {
			return fmt.Errorf("image: preparing %s: %w", s.SyntheticName(), err)
		}
	}
	return nil
}

// GenerateSynthetics runs every registered generator's Generate.
func GenerateSynthetics(img *Image) error {
	if err := img.require(PhaseFrozen, "GenerateSynthetics"); err != nil {
		return err
	}
	for _, s := range img.synthetics {
		if err := s.Generate(img); err != nil {
			return fmt.Errorf("image: generating %s: %w", s.SyntheticName(), err)
		}
	}
	return nil
}

// Finalizer is a step that runs after every other byte of the image is final.
//
// Order matters and is registration order. LC_UUID is computed over the
// finished image, and the code signature hashes everything before it including
// the UUID — so the signature must be registered last, and Finalize does not
// reorder.
type Finalizer interface {
	FinalizerName() string
	Finalize(img *Image) error
}

// AddFinalizer registers a finalizer.
func (img *Image) AddFinalizer(f Finalizer) error {
	if err := img.requireAtLeast(PhaseOpen, "AddFinalizer"); err != nil {
		return err
	}
	img.finalizers = append(img.finalizers, f)
	return nil
}

// Finalize runs every finalizer in registration order.
//
// This is not cosmetic and cannot be folded into the emit pass. The code
// signature's CodeDirectory hashes the file from offset zero up to the start
// of the signature, which covers the header, the load commands, and every
// segment — so it must run after the last byte of everything else is written.
func Finalize(img *Image) error {
	if err := img.require(PhaseFrozen, "Finalize"); err != nil {
		return err
	}
	for _, f := range img.finalizers {
		if err := f.Finalize(img); err != nil {
			return fmt.Errorf("image: %s: %w", f.FinalizerName(), err)
		}
	}
	return nil
}

// RawSource is an AtomSource over bytes already in hand.
//
// It is what a synthetic uses: Prepare creates the atom with a RawSource sized
// but empty, and Generate fills in Data once addresses are known. Sizing it up
// front and writing into it later is what keeps a stub's size available to
// layout while its content still depends on layout's result.
type RawSource struct {
	Data []byte

	// size is fixed at construction. Data may be shorter until Generate runs,
	// but never longer, or the atom would overrun its neighbour.
	size uint64
}

// NewRawSource returns a source of exactly n bytes.
func NewRawSource(n uint64) *RawSource {
	return &RawSource{Data: make([]byte, n), size: n}
}

// RawSourceOf returns a source over existing bytes.
func RawSourceOf(b []byte) *RawSource {
	return &RawSource{Data: b, size: uint64(len(b))}
}

func (r *RawSource) Size() uint64   { return r.size }
func (r *RawSource) Zerofill() bool { return false }

func (r *RawSource) Bytes() ([]byte, error) {
	if uint64(len(r.Data)) != r.size {
		return nil, fmt.Errorf("image: raw source is %d bytes, was sized at %d",
			len(r.Data), r.size)
	}
	return r.Data, nil
}

// Set replaces the source's content, which must be exactly its declared size.
func (r *RawSource) Set(b []byte) error {
	if uint64(len(b)) != r.size {
		return fmt.Errorf("image: raw source was sized at %d, got %d bytes", r.size, len(b))
	}
	r.Data = b
	return nil
}

// ZeroSource is an AtomSource for content that occupies address space and no
// file bytes: __bss, __common, and anything else in a zerofill section.
type ZeroSource struct{ N uint64 }

func (z ZeroSource) Size() uint64            { return z.N }
func (z ZeroSource) Zerofill() bool          { return true }
func (z ZeroSource) Bytes() ([]byte, error)  { return nil, nil }