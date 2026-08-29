package link

import (
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
	"github.com/vertex-language/macho/internal/binio"
)

// Chained fixups.
//
// The classic arrangement writes one opcode stream per fixup kind into
// __LINKEDIT and dyld walks them at load. The chained arrangement threads the
// fixups through the pointers themselves: each pointer's high bits hold the
// distance to the next fixup in the same page, so __LINKEDIT carries only a
// per-page starting offset and the import table. On a large image that is the
// difference between hundreds of kilobytes of opcodes and a few.
//
// It also means the pointer's on-disk value is not an address. Everything
// written by apply.go into a pointer field is overwritten here — which is why
// this runs as a Finalizer, after relocations have been applied and before the
// UUID and the signature hash the result.
//
// # What is not here
//
// The classic LC_DYLD_INFO_ONLY opcode path, which is the fallback for a
// deployment target older than the chained format. And arm64e: an
// authenticated pointer is a different chain entry carrying a key and a
// discriminator, and backend.PtrAuth exists to describe one but nothing
// encodes it. Both are reported rather than approximated.

// ---------------------------------------------------------------------------
// Constants that belong in macho/fixups.go. Delete if the names there match.
// ---------------------------------------------------------------------------

const (
	dyldChainedPtr64Offset       = 6  // stride 4, target is an offset from the header
	dyldChainedPtrARM64EUserland24 = 12 // stride 8, 24-bit bind ordinal

	dyldChainedImport = 1 // lib_ordinal:8, weak_import:1, name_offset:23

	dyldChainedPtrStartNone uint16 = 0xffff

	chainedFixupsHeaderSize  = 32 // seven uint32, padded to 8
	chainedStartsInSegSize   = 22 // before the page_start array
	chainedStride            = 4  // for DYLD_CHAINED_PTR_64_OFFSET
)

// fixups builds the LC_DYLD_CHAINED_FIXUPS payload and arranges for the chains
// themselves to be threaded through the data.
func (l *Linker) fixups(img *image.Image) error {
	if len(l.libs) == 0 {
		// Nothing dynamic to fix up against; the classic static case, which
		// this tree does not otherwise produce.
		return nil
	}
	// dyld expects a chained-fixups header to be present and well-formed
	// whenever the command exists at all, even with nothing to rebase or
	// bind — the header with a zero-entry import table is what "nothing to
	// do" looks like on disk. A present LC_DYLD_CHAINED_FIXUPS with a
	// zero-size payload is what "malformed import table" means to dyld.
	format, err := l.pointerFormat()
	if err != nil {
		return err
	}

	sites, err := l.fixupSites(img)
	if err != nil {
		return err
	}
	imports, strs, err := l.importTable(sites)
	if err != nil {
		return err
	}

	blob, segs, err := encodeChainedFixups(img, sites, imports, strs, format)
	if err != nil {
		return err
	}
	l.le.ChainedFixups = blob

	// A Finalizer rather than a step: the chain entries overwrite what
	// apply.go wrote into the same bytes, so they must go last, and the
	// signature must hash the result.
	return img.AddFinalizer(&chainFinalizer{l: l, sites: sites, segs: segs, format: format})
}

// pointerFormat picks the chain encoding for the target.
func (l *Linker) pointerFormat() (uint16, error) {
	switch {
	case l.target.SubCPU.Base() == macho.CPU_SUBTYPE_ARM64E:
		return dyldChainedPtrARM64EUserland24,
			fmt.Errorf("%w: arm64e authenticated chain entries", ErrUnimplemented)
	case l.target.Wide():
		return dyldChainedPtr64Offset, nil
	}
	// arm64_32 wants DYLD_CHAINED_PTR_32, whose chain entries carry a bias
	// and co-opt non-pointer values, and which nothing here encodes.
	return 0, fmt.Errorf("%w: 32-bit chained pointers", ErrUnimplemented)
}

// fixupSite is one pointer that dyld must write, resolved to a file position.
type fixupSite struct {
	addr   uint64 // virtual address of the pointer
	off    uint64 // file offset of the pointer
	seg    int    // index into the image's segment list
	bind   bool
	target uint64 // rebase: offset from the header
	ordinal uint32 // bind: index into the import table
	addend  uint64
	sym     *image.Sym
	weak    bool
}

// fixupSites resolves every recorded rebase and bind to an address, and sorts
// them.
//
// Sorted because the chain is a singly linked list in address order and each
// link stores a forward distance. Scan's insertion order is deterministic but
// it is not address order, and threading an unsorted list produces negative
// deltas that do not fit the field.
func (l *Linker) fixupSites(img *image.Image) ([]fixupSite, error) {
	base := img.BaseAddress()
	segs := img.Segments()

	out := make([]fixupSite, 0, l.reqs.Fixups())
	add := func(atom *image.Atom, off uint64, s *fixupSite) error {
		addr, err := atom.Addr()
		if err != nil {
			return err
		}
		fo, err := atom.FileOffset()
		if err != nil {
			return err
		}
		s.addr, s.off = addr+off, fo+off
		if s.addr%chainedStride != 0 {
			return fmt.Errorf("link: fixup at 0x%x in %s is not %d-byte aligned; a chain cannot reach it",
				s.addr, atomWhere(atom), chainedStride)
		}
		s.seg = -1
		for i, seg := range segs {
			if seg.FileSize > 0 && s.addr >= seg.VMAddr && s.addr < seg.VMAddr+seg.VMSize {
				s.seg = i
				break
			}
		}
		if s.seg < 0 {
			return fmt.Errorf("link: fixup at 0x%x falls in no segment", s.addr)
		}
		out = append(out, *s)
		return nil
	}

	for _, r := range l.reqs.Rebases() {
		if r.Auth != nil {
			return nil, fmt.Errorf("%w: authenticated rebase in %s", ErrUnimplemented, atomWhere(r.Atom))
		}
		// The pointer currently holds the address apply.go computed. The
		// chain entry stores it as an offset from the header, because dyld
		// adds the slide and an absolute address would be wrong by the base
		// in every process.
		site, err := backend.SiteFor(img, r.Atom, l.reqs)
		if err != nil {
			return nil, err
		}
		v, err := site.ReadN(r.Offset, l.be.WordSize())
		if err != nil {
			return nil, err
		}
		s := fixupSite{target: v - base}
		if err := add(r.Atom, r.Offset, &s); err != nil {
			return nil, err
		}
	}

	for _, b := range l.reqs.Binds() {
		if b.Auth != nil {
			return nil, fmt.Errorf("%w: authenticated bind in %s", ErrUnimplemented, atomWhere(b.Atom))
		}
		if b.Addend < 0 || b.Addend > 0xff {
			// The 64-bit bind entry carries eight bits of addend.
			// DYLD_CHAINED_IMPORT_ADDEND and _ADDEND64 exist for larger ones
			// and change the import table's element size, so escalating is a
			// format decision rather than a wider field.
			return nil, fmt.Errorf("link: bind to %s has addend %d; the chain entry holds 0..255 "+
				"and DYLD_CHAINED_IMPORT_ADDEND is unimplemented", b.Sym.Name, b.Addend)
		}
		s := fixupSite{bind: true, sym: b.Sym, weak: b.Weak, addend: uint64(b.Addend)}
		if err := add(b.Atom, b.Offset, &s); err != nil {
			return nil, err
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].addr < out[j].addr })
	return out, nil
}

// chainedImport is one entry of the import table.
type chainedImport struct {
	ordinal macho.LibOrdinal
	weak    bool
	nameOff uint32
}

// importTable assigns every bound symbol an index and builds the string blob.
//
// Two references to one symbol share an entry. The identity is the symbol
// rather than the name: under a two-level namespace "_malloc from libSystem"
// and "_malloc from libfoo" are different imports, and the library ordinal is
// part of the entry precisely so dyld does not have to search.
func (l *Linker) importTable(sites []fixupSite) ([]chainedImport, []byte, error) {
	index := make(map[*image.Sym]uint32)
	var imports []chainedImport
	strs := []byte{0} // offset 0 is the empty name, as everywhere else

	for i := range sites {
		if !sites[i].bind {
			continue
		}
		sym := sites[i].sym
		if n, ok := index[sym]; ok {
			sites[i].ordinal = n
			continue
		}
		off := uint32(len(strs))
		if off >= 1<<23 {
			return nil, nil, fmt.Errorf("link: import name table exceeds the 23-bit name offset")
		}
		strs = append(strs, sym.Name...)
		strs = append(strs, 0)

		n := uint32(len(imports))
		index[sym] = n
		sites[i].ordinal = n
		imports = append(imports, chainedImport{
			ordinal: sym.Ordinal, weak: sites[i].weak, nameOff: off,
		})
	}
	return imports, strs, nil
}

// segFixups is the per-segment page start table, kept so the finalizer does
// not recompute the grouping.
type segFixups struct {
	seg       int
	pageSize  uint64
	firstPage uint64   // page index of the segment's first page
	starts    []uint16 // one per page
	sites     [][]int  // indices into the site list, per page
}

// encodeChainedFixups builds the LC_DYLD_CHAINED_FIXUPS payload.
func encodeChainedFixups(img *image.Image, sites []fixupSite, imports []chainedImport,
	strs []byte, format uint16) ([]byte, []segFixups, error) {

	segs := img.Segments()
	pageSize := img.PageSize()

	// Group by segment and then by page. page_start holds the offset of the
	// first fixup in each page, or DYLD_CHAINED_PTR_START_NONE; every later
	// fixup in the page is reached through the previous one's next field.
	byseg := make(map[int]*segFixups)
	for i, s := range sites {
		g := byseg[s.seg]
		if g == nil {
			seg := segs[s.seg]
			pages := (seg.VMSize + pageSize - 1) / pageSize
			g = &segFixups{
				seg: s.seg, pageSize: pageSize,
				starts: make([]uint16, pages),
				sites:  make([][]int, pages),
			}
			for p := range g.starts {
				g.starts[p] = dyldChainedPtrStartNone
			}
			byseg[s.seg] = g
		}
		seg := segs[s.seg]
		p := (s.addr - seg.VMAddr) / pageSize
		inPage := (s.addr - seg.VMAddr) % pageSize
		if g.starts[p] == dyldChainedPtrStartNone {
			g.starts[p] = uint16(inPage)
		}
		g.sites[p] = append(g.sites[p], i)
	}

	order := make([]segFixups, 0, len(byseg))
	for i := range segs {
		if g, ok := byseg[i]; ok {
			order = append(order, *g)
		}
	}

	b := binio.NewBuf(img.Endian().Order())

	// starts_in_image comes first after the header; the imports and the
	// strings follow it, and each offset in the header is from the start of
	// the payload.
	startsOff := uint32(chainedFixupsHeaderSize)

	var starts binio.Buf
	_ = starts
	sb := binio.NewBuf(img.Endian().Order())
	sb.U32(uint32(len(segs)))
	segOffSlots := make([]*binio.Ref32, len(segs))
	for i := range segs {
		segOffSlots[i] = sb.Reserve32()
	}
	for i := range segs {
		g, ok := byseg[i]
		if !ok {
			// A segment with no fixups gets a zero offset, which dyld reads
			// as "nothing here" rather than as an offset to the header.
			segOffSlots[i].Set(0)
			continue
		}
		sb.Align(8)
		segOffSlots[i].Set(uint32(sb.Len()))
		seg := segs[i]
		sb.U32(uint32(chainedStartsInSegSize + len(g.starts)*2))
		sb.U16(uint16(pageSize))
		sb.U16(format)
		sb.U64(seg.VMAddr - img.BaseAddress())
		sb.U32(0) // max_valid_pointer: 64-bit only, unused
		sb.U16(uint16(len(g.starts)))
		for _, s := range g.starts {
			sb.U16(s)
		}
	}
	if err := sb.Err(); err != nil {
		return nil, nil, err
	}
	startsBlob := sb.Bytes()

	importsOff := align32(startsOff+uint32(len(startsBlob)), 4)
	symbolsOff := importsOff + uint32(len(imports))*4

	b.U32(0) // fixups_version
	b.U32(startsOff)
	b.U32(importsOff)
	b.U32(symbolsOff)
	b.U32(uint32(len(imports)))
	b.U32(dyldChainedImport)
	b.U32(0) // symbols_format: uncompressed
	b.Zero(chainedFixupsHeaderSize - b.Len())

	b.Raw(startsBlob)
	b.Zero(int(importsOff) - b.Len())
	for _, im := range imports {
		v := uint32(uint8(im.ordinal)) | (im.nameOff << 9)
		if im.weak {
			v |= 1 << 8
		}
		b.U32(v)
	}
	b.Raw(strs)
	b.Align(8)

	if err := b.Err(); err != nil {
		return nil, nil, err
	}
	return b.Bytes(), order, nil
}

func align32(v, n uint32) uint32 { return (v + n - 1) &^ (n - 1) }

// chainFinalizer threads the chains through the image's pointers.
type chainFinalizer struct {
	l      *Linker
	sites  []fixupSite
	segs   []segFixups
	format uint16
}

func (c *chainFinalizer) FinalizerName() string { return "chained fixups" }

// Finalize overwrites each fixup site with its chain entry.
//
// The entry replaces whatever the relocation wrote — a rebase's target is
// already in the entry, and a bind's pointer value is supplied entirely by
// dyld — so nothing of the previous contents survives, and the order of this
// against apply.go is not negotiable.
func (c *chainFinalizer) Finalize(img *image.Image) error {
	for _, g := range c.segs {
		for _, page := range g.sites {
			for i, si := range page {
				s := c.sites[si]

				next := uint64(0)
				if i+1 < len(page) {
					d := c.sites[page[i+1]].addr - s.addr
					if d%chainedStride != 0 || d/chainedStride > 0xfff {
						return fmt.Errorf("link: fixups at 0x%x and 0x%x are %d bytes apart; "+
							"the chain's next field reaches %d",
							s.addr, c.sites[page[i+1]].addr, d, 0xfff*chainedStride)
					}
					next = d / chainedStride
				}

				var v uint64
				if s.bind {
					if s.ordinal > 0xffffff {
						return fmt.Errorf("link: %d imports; a bind entry's ordinal holds 24 bits",
							s.ordinal)
					}
					v = uint64(s.ordinal) |
						s.addend<<24 |
						next<<51 |
						1<<63
				} else {
					if s.target >= 1<<36 {
						return fmt.Errorf("link: rebase target 0x%x exceeds the 36-bit field; "+
							"the image is larger than 64 GB", s.target)
					}
					v = s.target | next<<51
				}
				buf := make([]byte, 8)
				img.Endian().Order().PutUint64(buf, v)
				if err := img.WriteAt(s.off, buf); err != nil {
					return err
				}
			}
		}
	}
	return nil
}