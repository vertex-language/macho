package ar

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/vertex-language/macho/internal/binio"
)

// File is a parsed archive.
type File struct {
	ext    binio.Extent
	closer io.Closer

	// Members is every member except the table of contents, in file order.
	// The TOC is excluded because it is metadata about the archive rather than
	// a member of it, and a caller iterating members to link them would
	// otherwise have to know to skip it.
	Members []*Member

	symdef *Member

	tocOnce sync.Once
	toc     *TOC
	tocErr  error
}

// Member is one archive member.
type Member struct {
	// Name is the member's resolved name, with the extended form already
	// decoded and trailing blanks trimmed.
	Name string

	// HeaderOffset is the offset of the member's ar_hdr from the start of the
	// archive. This is the quantity the table of contents stores, so it is the
	// one a TOC lookup returns.
	HeaderOffset int64

	// Offset and Size bound the member's contents: past the header and past
	// the extended name, if any.
	//
	// Size may include trailing alignment padding. Darwin counts a member's
	// padding inside ar_size, so there is no way to recover the exact original
	// length from the archive alone — for a Mach-O it does not matter, since
	// the load commands describe the file's extent, and for anything else the
	// writer's caller knows what it put in.
	Offset int64
	Size   int64

	Date int64
	UID  int
	GID  int
	Mode uint32

	f *File
}

// Extent returns a bounded view of the member's contents, which is what
// obj.NewFile consumes. Nothing is copied.
func (m *Member) Extent() (binio.Extent, error) {
	return m.f.ext.Slice(m.Offset, m.Size)
}

// Bytes reads the member into memory.
func (m *Member) Bytes() ([]byte, error) {
	e, err := m.Extent()
	if err != nil {
		return nil, err
	}
	return e.Bytes()
}

func (m *Member) String() string {
	return fmt.Sprintf("%s (%d bytes at %d)", m.Name, m.Size, m.Offset)
}

// Open opens an archive file.
func Open(name string) (*File, error) {
	bf, err := binio.Open(name)
	if err != nil {
		return nil, err
	}
	f, err := NewFile(bf.Extent())
	if err != nil {
		bf.Close()
		return nil, err
	}
	f.closer = bf
	return f, nil
}

// NewFile parses an archive out of an extent.
//
// The extent may be a whole file or one slice of a universal file — a
// universal static library is a fat file whose slices are archives, and
// fat.Arch.Extent produces exactly what this wants.
func NewFile(ext binio.Extent) (*File, error) {
	if !ext.Valid() {
		return nil, fmt.Errorf("ar: NewFile called with a zero Extent")
	}
	head, err := ext.Head(MagicSize)
	if err != nil {
		return nil, err
	}
	if len(head) < MagicSize || string(head) != Magic {
		return nil, ErrNotArchive
	}

	f := &File{ext: ext}
	size := ext.Size()
	off := int64(MagicSize)

	for first := true; off < size; first = false {
		if size-off < HeaderSize {
			// Trailing bytes too short to be a header. Some writers leave a
			// pad byte at the end; anything longer is a truncated member and
			// worth reporting.
			if size-off <= 1 {
				break
			}
			return nil, fmt.Errorf("%w: %d trailing bytes at %d", ErrBadHeader, size-off, off)
		}

		raw, err := ext.Read(off, HeaderSize)
		if err != nil {
			return nil, err
		}
		h, err := decodeHeader(raw, off)
		if err != nil {
			return nil, err
		}

		// SysV/GNU archives share the file magic and are told apart by their
		// special member names. Detecting them on the first member is enough:
		// the symbol table is required to be first if present, and "//"
		// follows it.
		if first && isSysVName(h.Name) {
			return nil, fmt.Errorf("%w: first member is %q", ErrSysVArchive, h.Name)
		}

		dataOff := off + HeaderSize
		if h.Size > size-dataOff {
			return nil, fmt.Errorf("%w: member at %d claims %d bytes, %d remain",
				ErrBadHeader, off, h.Size, size-dataOff)
		}

		name := h.Name
		dataSize := h.Size
		if n, ok := extNameLen(h.Name); ok {
			if int64(n) > dataSize {
				return nil, fmt.Errorf("%w: extended name at %d is %d bytes of a %d-byte member",
					ErrBadHeader, off, n, dataSize)
			}
			nb, err := ext.Read(dataOff, int64(n))
			if err != nil {
				return nil, err
			}
			// The name is NUL-padded to its rounded length, so it is trimmed
			// at the first NUL rather than at the field's end.
			name = strings.TrimRight(string(nb), "\x00")
			dataOff += int64(n)
			dataSize -= int64(n)
		}

		m := &Member{
			Name:         name,
			HeaderOffset: off,
			Offset:       dataOff,
			Size:         dataSize,
			Date:         h.Date,
			UID:          h.UID,
			GID:          h.GID,
			Mode:         h.Mode,
			f:            f,
		}
		if first && IsSymdef(name) {
			f.symdef = m
		} else {
			f.Members = append(f.Members, m)
		}

		// Advance by the declared size, then round to even.
		//
		// Darwin counts a member's padding inside ar_size, so the rounding is
		// a no-op there. Other writers pad to an even offset without counting
		// the pad byte, and the rounding is what keeps those readable. Doing
		// both costs nothing and is why this reader handles archives it did
		// not write.
		next := roundUp64(dataOff+dataSize, 2)
		if next <= off {
			return nil, fmt.Errorf("%w: member at %d does not advance", ErrBadHeader, off)
		}
		off = next
	}
	return f, nil
}

// Close releases the underlying file if this File opened it.
func (f *File) Close() error {
	if f.closer != nil {
		return f.closer.Close()
	}
	return nil
}

// Size returns the total size of the archive.
func (f *File) Size() int64 { return f.ext.Size() }

// Member returns the first member with the given name, or nil.
//
// Names are not unique: an archive may legitimately contain two members called
// foo.o, from different directories. A caller that cares must walk Members.
func (f *File) Member(name string) *Member {
	for _, m := range f.Members {
		if m.Name == name {
			return m
		}
	}
	return nil
}

// isSysVName reports whether a first-member name identifies a SysV/GNU
// archive. All three special names begin with "/", which a BSD member name
// never does.
func isSysVName(name string) bool {
	switch name {
	case "/", "//", "/SYM64/":
		return true
	}
	return strings.HasPrefix(name, "/")
}

// TOC is the archive's table of contents: which member defines which symbol.
type TOC struct {
	// Name is the symdef member's name, which is what says whether the table
	// is sorted and whether it uses 64-bit fields.
	Name string

	Wide   bool
	Sorted bool

	Entries []TOCEntry
}

// TOCEntry maps one symbol to the member that defines it.
type TOCEntry struct {
	Symbol string

	// MemberHeaderOffset is an offset to the member's ar_hdr, not to its
	// contents. That is what ran_off holds, and treating it as a data offset
	// lands 60-plus bytes into the header of the wrong thing.
	MemberHeaderOffset int64
}

// TOC returns the archive's table of contents.
func (f *File) TOC() (*TOC, error) {
	f.tocOnce.Do(func() { f.toc, f.tocErr = f.readTOC() })
	return f.toc, f.tocErr
}

// Lookup returns the member defining sym.
//
// It walks rather than binary-searches even when the table says it is sorted,
// because a table claiming to be sorted and not being one is a file this
// package must not trust for correctness. Archives are small enough that the
// difference does not pay for the risk.
func (f *File) Lookup(sym string) (*Member, error) {
	toc, err := f.TOC()
	if err != nil {
		return nil, err
	}
	for _, e := range toc.Entries {
		if e.Symbol != sym {
			continue
		}
		for _, m := range f.Members {
			if m.HeaderOffset == e.MemberHeaderOffset {
				return m, nil
			}
		}
		return nil, fmt.Errorf("%w: symbol %q names offset %d, which is no member's header",
			ErrBadTOC, sym, e.MemberHeaderOffset)
	}
	return nil, nil
}

func (f *File) readTOC() (*TOC, error) {
	if f.symdef == nil {
		return nil, ErrNoTOC
	}
	data, err := f.symdef.Bytes()
	if err != nil {
		return nil, err
	}

	toc := &TOC{
		Name:   f.symdef.Name,
		Wide:   symdefWide(f.symdef.Name),
		Sorted: symdefSorted(f.symdef.Name),
	}

	// The table is written in the byte order of the architecture the archive
	// was built for, and nothing in it says which that is. The size prefix is
	// the discriminator: it must be a multiple of the entry size and must fit
	// the member, and a byte-swapped value essentially never satisfies both.
	ord, entSize, err := tocByteOrder(data, toc.Wide)
	if err != nil {
		return nil, err
	}

	c := binio.NewCursor(data, ord)
	ranSize := readWord(c, toc.Wide)
	if err := c.Err(); err != nil {
		return nil, err
	}
	n, ok := c.Count(ranSize/uint64(entSize), entSize, "ranlib entries")
	if !ok {
		return nil, fmt.Errorf("%w: %v", ErrBadTOC, c.Err())
	}

	type raw struct{ strx, off uint64 }
	entries := make([]raw, 0, n)
	for i := 0; i < n; i++ {
		strx := readWord(c, toc.Wide)
		off := readWord(c, toc.Wide)
		entries = append(entries, raw{strx, off})
	}
	if err := c.Err(); err != nil {
		return nil, err
	}

	strSize := readWord(c, toc.Wide)
	if err := c.Err(); err != nil {
		return nil, err
	}
	if strSize > uint64(c.Remaining()) {
		return nil, fmt.Errorf("%w: string table claims %d bytes, %d remain",
			ErrBadTOC, strSize, c.Remaining())
	}
	strs := c.Next(int(strSize))
	if err := c.Err(); err != nil {
		return nil, err
	}

	for _, e := range entries {
		name, err := cstringAt(strs, e.strx)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadTOC, err)
		}
		if e.off > uint64(f.ext.Size()) {
			return nil, fmt.Errorf("%w: symbol %q names offset %d past the %d-byte archive",
				ErrBadTOC, name, e.off, f.ext.Size())
		}
		toc.Entries = append(toc.Entries, TOCEntry{
			Symbol:             name,
			MemberHeaderOffset: int64(e.off),
		})
	}
	return toc, nil
}

// tocByteOrder decides which order the table of contents was written in, and
// returns the size of one ranlib entry.
func tocByteOrder(data []byte, wide bool) (binary.ByteOrder, int, error) {
	word, entSize := 4, 8
	if wide {
		word, entSize = 8, 16
	}
	if len(data) < word {
		return nil, 0, fmt.Errorf("%w: %d bytes is too short for a size prefix", ErrBadTOC, len(data))
	}

	plausible := func(ord binary.ByteOrder) bool {
		var v uint64
		if wide {
			v = ord.Uint64(data[:8])
		} else {
			v = uint64(ord.Uint32(data[:4]))
		}
		return v%uint64(entSize) == 0 && v <= uint64(len(data)-word)
	}
	if plausible(binary.LittleEndian) {
		return binary.LittleEndian, entSize, nil
	}
	if plausible(binary.BigEndian) {
		return binary.BigEndian, entSize, nil
	}
	return nil, 0, fmt.Errorf("%w: size prefix is implausible in either byte order", ErrBadTOC)
}

func readWord(c *binio.Cursor, wide bool) uint64 {
	if wide {
		return c.U64()
	}
	return uint64(c.U32())
}

func cstringAt(strs []byte, off uint64) (string, error) {
	if off >= uint64(len(strs)) {
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