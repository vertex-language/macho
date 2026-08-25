package image

import (
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
)

// Segment is a mapped region of the output.
//
// It is a first-class owner of its sections, not a view over them. ELF infers
// segments from section flags; Mach-O does not, and the difference is
// load-bearing here — __DATA_CONST and __DATA hold sections with identical
// flags and differ only in that one is made read-only after fixups are
// applied. No flag distinguishes them, so nothing can rediscover the grouping
// from the sections alone.
type Segment struct {
	Name string

	MaxProt  macho.Prot
	InitProt macho.Prot
	Flags    macho.SegFlags

	// Assigned by link between Seal and Freeze.
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64

	sections []*Section
	img      *Image
	index    int

	// assigned records whether address assignment has run, so that reading an
	// address early is an error rather than a plausible zero — __PAGEZERO's
	// address really is zero.
	assigned bool
}

// Segment returns the named segment, creating it if the image has none.
//
// Protections come from the name for the segments the format gives meaning to;
// anything else defaults to read-write, which is the conservative choice
// because a segment that turns out to need write access and lacks it faults at
// runtime, while an unnecessary write bit only loses page sharing.
func (img *Image) Segment(name string) (*Segment, error) {
	if s, ok := img.segByName[name]; ok {
		return s, nil
	}
	if err := img.require(PhaseOpen, "creating a segment"); err != nil {
		return nil, err
	}
	if !macho.ValidName(name) {
		return nil, fmt.Errorf("image: segment name %q does not fit %d bytes",
			name, macho.SegNameSize)
	}
	maxProt, initProt := defaultProt(name)
	seg := &Segment{Name: name, MaxProt: maxProt, InitProt: initProt, img: img}
	img.segments = append(img.segments, seg)
	img.segByName[name] = seg
	return seg, nil
}

// FindSegment returns the named segment, or nil.
func (img *Image) FindSegment(name string) *Segment {
	return img.segByName[name]
}

// Segments returns every segment in output order.
func (img *Image) Segments() []*Segment { return img.segments }

func defaultProt(name string) (max, init macho.Prot) {
	const (
		r  = macho.VM_PROT_READ
		w  = macho.VM_PROT_WRITE
		x  = macho.VM_PROT_EXECUTE
		rw = r | w
		rx = r | x
	)
	switch name {
	case macho.SEG_PAGEZERO:
		// No access at all: the entire point is that touching it faults.
		return macho.VM_PROT_NONE, macho.VM_PROT_NONE
	case macho.SEG_TEXT:
		return rx, rx
	case macho.SEG_LINKEDIT:
		return r, r
	case macho.SEG_DATA_CONST, macho.SEG_AUTH_CONST:
		// Writable initially so fixups can be applied, then made read-only.
		// SG_READ_ONLY is what asks dyld for that, and it is set by link once
		// it knows the segment has no runtime-writable content.
		return rw, rw
	}
	return rw, rw
}

// Sections returns the segment's sections in output order.
func (seg *Segment) Sections() []*Section { return seg.sections }

// Empty reports whether the segment has no sections.
//
// __PAGEZERO is legitimately empty and is not dropped; every other empty
// segment is one link created and never used, and emitting a load command for
// it wastes a mapping.
func (seg *Segment) Empty() bool { return len(seg.sections) == 0 }

// Index returns the segment's position in output order.
func (seg *Segment) Index() int { return seg.index }

// SetPlacement records the segment's assigned addresses and offsets.
func (seg *Segment) SetPlacement(vmaddr, vmsize, fileoff, filesize uint64) error {
	if err := seg.img.require(PhaseSealed, "placing a segment"); err != nil {
		return err
	}
	seg.VMAddr, seg.VMSize = vmaddr, vmsize
	seg.FileOff, seg.FileSize = fileoff, filesize
	seg.assigned = true
	return nil
}

// Placed reports whether the segment has been assigned an address.
func (seg *Segment) Placed() bool { return seg.assigned }

// segmentRank orders the segments a linked image contains.
//
// The order is not arbitrary. __PAGEZERO must be first because it starts at
// address zero. __TEXT must be the first segment with content because it
// begins at file offset 0 and covers the header. __LINKEDIT must be last
// because the code signature lives at its end and hashes everything before it.
// The middle is convention, chosen so writable data is contiguous.
func segmentRank(name string) int {
	switch name {
	case macho.SEG_PAGEZERO:
		return 0
	case macho.SEG_TEXT:
		return 1
	case macho.SEG_DATA_CONST:
		return 2
	case macho.SEG_AUTH_CONST:
		return 3
	case macho.SEG_AUTH:
		return 4
	case macho.SEG_DATA:
		return 5
	case macho.SEG_LINKEDIT:
		return 100
	}
	return 50
}

// orderSegments sorts the segments into output order and assigns indices.
func (img *Image) orderSegments() {
	sort.SliceStable(img.segments, func(i, j int) bool {
		ri, rj := segmentRank(img.segments[i].Name), segmentRank(img.segments[j].Name)
		if ri != rj {
			return ri < rj
		}
		return img.segments[i].Name < img.segments[j].Name
	})
	for i, seg := range img.segments {
		seg.index = i
	}
}

// validate checks the segment's sections against everything the format
// requires and nothing downstream can detect.
func (seg *Segment) validate() error {
	var (
		prevEnd  uint64
		seenZero bool
		first    = true
	)
	for _, sec := range seg.sections {
		if !sec.assigned {
			return fmt.Errorf("%w: %s was never assigned an address", ErrNoSize, sec.Key.Name)
		}
		if sec.Align != 0 && sec.Addr%uint64(sec.Align) != 0 {
			return fmt.Errorf("%w: %s at 0x%x violates its %d-byte alignment",
				ErrLayout, sec.Key.Name, sec.Addr, sec.Align)
		}
		// A zerofill section occupies address space and no file bytes, so any
		// section placed after one in the same segment would have a file
		// offset that no longer tracks its address — the segment could not be
		// described as a single contiguous mapping.
		if sec.Zerofill() {
			seenZero = true
		} else if seenZero {
			return fmt.Errorf("%w: %s has file contents but follows a zerofill section in %s",
				ErrLayout, sec.Key.Name, seg.Name)
		}
		if !first && sec.Addr < prevEnd {
			return fmt.Errorf("%w: %s begins at 0x%x, inside the section ending at 0x%x",
				ErrLayout, sec.Key.Name, sec.Addr, prevEnd)
		}
		prevEnd = sec.Addr + sec.Size
		first = false
	}
	return nil
}