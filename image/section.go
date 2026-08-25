package image

import (
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
)

// SectionKey is an output section's full identity.
//
// The name pair alone is not enough. __DATA,__const and __DATA_CONST,__const
// are different sections that must never merge, which the segment half
// handles — but type and attributes are in the key too, because merging an
// S_ZEROFILL section into an S_REGULAR one of the same name would give the
// result file bytes for content that has none, and merging across attributes
// would silently drop S_ATTR_NO_DEAD_STRIP from half the contributions.
type SectionKey struct {
	Name  macho.SecName
	Type  macho.SecType
	Attrs macho.SecAttrs
}

func (k SectionKey) String() string {
	return fmt.Sprintf("%s [%v]", k.Name, k.Type)
}

// Section is one output section: a run of atoms with a common type and
// attributes, placed inside a segment.
type Section struct {
	Key SectionKey

	// Align is the section's alignment in bytes, the maximum over its atoms.
	// Bytes rather than log2 throughout this tree; the wire edge converts.
	Align uint32

	// Assigned by link between Seal and Freeze.
	Addr uint64
	Size uint64
	Off  uint64

	// Reserved1 and Reserved2 are the overloaded on-disk fields. They are set
	// through named accessors so no caller writes a raw reserved word.
	reserved1 uint32
	reserved2 uint32

	atoms []*Atom
	seg   *Segment
	img   *Image
	index int

	assigned bool
}

// Section returns the output section for a key, creating it if needed.
//
// The segment is created too if the image does not have it, because a section
// cannot exist outside one and requiring the caller to create both in the
// right order buys nothing.
func (img *Image) Section(key SectionKey) (*Section, error) {
	if s, ok := img.secByKey[key]; ok {
		return s, nil
	}
	if err := img.require(PhaseOpen, "creating a section"); err != nil {
		return nil, err
	}
	if !key.Name.Valid() {
		return nil, fmt.Errorf("image: section name %s does not fit its fields", key.Name)
	}
	seg, err := img.Segment(key.Name.Segment)
	if err != nil {
		return nil, err
	}
	sec := &Section{Key: key, Align: 1, seg: seg, img: img}
	seg.sections = append(seg.sections, sec)
	img.sections = append(img.sections, sec)
	img.secByKey[key] = sec
	return sec, nil
}

// FindSection returns the section for a key, or nil.
func (img *Image) FindSection(key SectionKey) *Section { return img.secByKey[key] }

// Sections returns every output section in n_sect order.
func (img *Image) Sections() []*Section { return img.sections }

// Segment returns the segment this section belongs to.
func (sec *Section) Segment() *Segment { return sec.seg }

// Index returns the section's 1-based n_sect ordinal.
func (sec *Section) Index() int { return sec.index }

// Zerofill reports whether the section occupies no file bytes.
func (sec *Section) Zerofill() bool { return sec.Key.Type.Zerofill() }

// Atoms returns the section's atoms in placement order.
func (sec *Section) Atoms() []*Atom { return sec.atoms }

// AddAtom appends an atom and widens the section's alignment to fit it.
//
// The section's alignment is the maximum over its atoms rather than something
// chosen: an atom placed at an address that does not satisfy its own alignment
// is a miscompile on every architecture with alignment-sensitive loads, and
// the section's address is the only thing the format lets a linker control.
func (sec *Section) AddAtom(a *Atom) error {
	if err := sec.img.require(PhaseOpen, "adding an atom"); err != nil {
		return err
	}
	if a.Align > sec.Align {
		sec.Align = a.Align
	}
	a.Sec = sec
	sec.atoms = append(sec.atoms, a)
	return nil
}

// LiveAtoms returns the atoms that survived dead-stripping and coalescing.
//
// The two flags are checked separately and stay separate. Coalesced means the
// atom lost a weak-definition election during resolve and is permanently gone;
// Live means it survived -dead_strip. Collapsing them into one flag was a real
// bug class in earlier designs of this linker, because an atom can lose an
// election and still be referenced, and the reference has to be redirected to
// the winner rather than the atom being resurrected.
func (sec *Section) LiveAtoms() []*Atom {
	out := make([]*Atom, 0, len(sec.atoms))
	for _, a := range sec.atoms {
		if a.Live && !a.Coalesced {
			out = append(out, a)
		}
	}
	return out
}

// SetPlacement records the section's assigned address and file offset.
func (sec *Section) SetPlacement(addr, size, off uint64) error {
	if err := sec.img.require(PhaseSealed, "placing a section"); err != nil {
		return err
	}
	sec.Addr, sec.Size, sec.Off = addr, size, off
	sec.assigned = true
	return nil
}

// SetIndirectIndex sets reserved1 for a pointer or stub section: the section's
// starting index into the shared indirect symbol table.
func (sec *Section) SetIndirectIndex(i uint32) error {
	if !sec.Key.Type.Indirect() {
		return fmt.Errorf("image: %s is %v and has no indirect symbol entries",
			sec.Key.Name, sec.Key.Type)
	}
	sec.reserved1 = i
	return nil
}

// SetStubSize sets reserved2 for an S_SYMBOL_STUBS section: the byte size of
// one stub.
func (sec *Section) SetStubSize(n uint32) error {
	if sec.Key.Type != macho.S_SYMBOL_STUBS {
		return fmt.Errorf("image: %s is not a stub section", sec.Key.Name)
	}
	sec.reserved2 = n
	return nil
}

// Reserved returns the raw reserved words, for the emitter.
func (sec *Section) Reserved() (r1, r2 uint32) { return sec.reserved1, sec.reserved2 }

// sectionRank orders sections within a segment.
//
// Two constraints are real and the rest is convention. Zerofill sections must
// come last, because they have no file bytes and anything after one would
// break the segment's single contiguous mapping. And within __LINKEDIT the
// chained-fixups data must come first — dyld reads it before anything else in
// the segment, and lld fixed a real bug to guarantee that ordering.
func sectionRank(sec *Section) int {
	if sec.Zerofill() {
		return 1000
	}
	switch sec.Key.Name.Section {
	case macho.SECT_TEXT:
		return 0
	case macho.SECT_STUBS:
		return 1
	case macho.SECT_STUB_HELPER:
		return 2
	case macho.SECT_CSTRING:
		return 10
	case macho.SECT_UNWIND_INFO:
		return 20
	case macho.SECT_EH_FRAME:
		return 21
	case macho.SECT_CONST:
		return 30
	case macho.SECT_GOT, macho.SECT_NL_SYMBOL_PTR:
		return 40
	case macho.SECT_LA_SYMBOL_PTR:
		return 41
	case macho.SECT_MOD_INIT_FUNC:
		return 50
	case macho.SECT_MOD_TERM_FUNC:
		return 51
	case macho.SECT_DATA:
		return 60
	}
	return 100
}

// OrderSections sorts every segment's sections into output order and assigns
// n_sect ordinals across the whole image.
//
// Ordinals are global and 1-based, running through the segments in output
// order, because a symbol's n_sect is a single byte indexing the flattened
// list. link may reorder within a segment first — -order_file and section
// ordering are its business — but the ordinal assignment has to happen here,
// once, after everything else has settled.
func (img *Image) OrderSections() error {
	if err := img.requireAtLeast(PhaseSealed, "OrderSections"); err != nil {
		return err
	}
	n := 0
	for _, seg := range img.segments {
		sort.SliceStable(seg.sections, func(i, j int) bool {
			return sectionRank(seg.sections[i]) < sectionRank(seg.sections[j])
		})
		for _, sec := range seg.sections {
			n++
			sec.index = n
		}
	}
	if n > macho.MAX_SECT {
		return fmt.Errorf("image: %d sections, the n_sect field holds %d", n, macho.MAX_SECT)
	}
	// Rebuild the flat list so Sections() matches ordinal order.
	img.sections = img.sections[:0]
	for _, seg := range img.segments {
		img.sections = append(img.sections, seg.sections...)
	}
	return nil
}

// assignOrdinals is the Seal-time pass, before link has reordered anything.
func (img *Image) assignOrdinals() { _ = img.OrderSections() }