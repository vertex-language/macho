package ar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"github.com/vertex-language/macho/internal/binio"
)

// Options configures a Writer.
type Options struct {
	// Deterministic zeroes the timestamp, uid, and gid on every member and
	// uses a fixed mode, so two runs over the same inputs produce identical
	// bytes. It is the right default for a build system; the metadata is
	// recorded by the format and used by nothing in the link path.
	Deterministic bool

	// ModTime is the timestamp for every member when Deterministic is false.
	// The zero value means the time Close runs.
	ModTime time.Time

	UID, GID int

	// Mode defaults to 0644 when zero.
	Mode uint32
}

// Input is one member to add.
type Input struct {
	// Name is the member's name. Only the base name is meaningful to a
	// linker, but nothing here trims a path — the caller decides.
	Name string

	Data []byte

	// Symbols are the names this member defines and that the table of contents
	// should point at it for. Nothing in this package computes them: ar has no
	// idea what a Mach-O file is, and giving it one would make an archive
	// writer depend on an object reader for no benefit. The caller passes the
	// external defined symbols it already decoded.
	//
	// A member with no symbols is fine. It simply appears in no TOC entry, and
	// a linker pulls it in only if something names it explicitly.
	Symbols []string
}

// Writer builds an archive.
//
// Like obj.Writer, errors latch and nothing is written until Close: the table
// of contents comes first in the file and holds offsets to every member, so no
// byte can be placed until every member is known.
type Writer struct {
	out  io.Writer
	opts Options

	inputs []Input
	names  map[string]bool

	closed bool
	err    error
}

// NewWriter returns a Writer that emits to out when Close is called.
func NewWriter(out io.Writer, opts Options) *Writer {
	return &Writer{out: out, opts: opts, names: make(map[string]bool)}
}

func (w *Writer) fail(err error) {
	if w.err == nil {
		w.err = err
	}
}

// Err returns the first error the writer hit, or nil.
func (w *Writer) Err() error { return w.err }

// Add appends a member.
//
// Duplicate names are allowed — an archive may legitimately hold two members
// called foo.o from different directories — but a duplicate makes the sorted
// table of contents unusable if both define the same symbol, and Close falls
// back to the unsorted form when that happens.
func (w *Writer) Add(in Input) {
	if w.closed {
		w.fail(errors.New("ar: Add after Close"))
		return
	}
	if w.err != nil {
		return
	}
	if in.Name == "" {
		w.fail(errors.New("ar: member with an empty name"))
		return
	}
	if IsSymdef(in.Name) {
		w.fail(fmt.Errorf("ar: %q is reserved for the table of contents", in.Name))
		return
	}
	w.inputs = append(w.inputs, in)
}

// Close lays the archive out and writes it. It is idempotent-guarded.
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

// tocSymbol is one pending table-of-contents entry.
type tocSymbol struct {
	name   string
	member int
	strx   uint64
	off    uint64
}

func (w *Writer) emit() error {
	// Collect the symbols and decide the table's form before anything is
	// sized, since the name of the symdef member is part of its own size.
	var syms []tocSymbol
	for i, in := range w.inputs {
		for _, s := range in.Symbols {
			if s == "" {
				return fmt.Errorf("ar: member %q lists an empty symbol name", in.Name)
			}
			syms = append(syms, tocSymbol{name: s, member: i})
		}
	}

	// Sort by name so the table can be binary-searched, then check for
	// duplicates. Two members defining one symbol cannot be expressed in a
	// sorted table — a search finds one of them and never learns the other
	// exists — so the fallback is the unsorted form, ordered by member offset,
	// which a linker scans linearly. This is what ranlib does, and the reason
	// both forms still exist.
	sort.SliceStable(syms, func(i, j int) bool { return syms[i].name < syms[j].name })
	sorted := true
	for i := 1; i < len(syms); i++ {
		if syms[i].name == syms[i-1].name {
			sorted = false
			break
		}
	}
	if !sorted {
		sort.SliceStable(syms, func(i, j int) bool { return syms[i].member < syms[j].member })
	}

	// The string table is built in the table's final order, so a sorted table
	// also has its strings in sorted order — which is not required, but makes
	// a hex dump legible and a golden diff stable.
	var strs []byte
	for i := range syms {
		syms[i].strx = uint64(len(strs))
		strs = append(strs, syms[i].name...)
		strs = append(strs, 0)
	}
	strs = append(strs, make([]byte, roundUp(len(strs), MemberAlign)-len(strs))...)

	// Lay out assuming 32-bit fields, then promote if any offset overflowed.
	// Promotion widens every field and therefore only pushes offsets later, so
	// as in the fat writer a second pass cannot un-promote.
	wide := false
	offsets, tocSize := w.place(syms, strs, wide)
	for _, off := range offsets {
		if off > math.MaxUint32 {
			wide = true
			break
		}
	}
	if wide {
		offsets, tocSize = w.place(syms, strs, wide)
	}
	for i := range syms {
		syms[i].off = offsets[syms[i].member]
	}

	b := binio.NewBuf(tocByteOrderOut())
	b.String(Magic)

	if err := w.writeTOC(b, syms, strs, wide, sorted, tocSize); err != nil {
		return err
	}
	for i, in := range w.inputs {
		if uint64(b.Len()) != offsets[i] {
			return fmt.Errorf("ar: internal layout error: member %q at %d, expected %d",
				in.Name, b.Len(), offsets[i])
		}
		if err := writeMember(b, in.Name, in.Data, w.header()); err != nil {
			return err
		}
	}
	if err := b.Err(); err != nil {
		return err
	}
	_, err := w.out.Write(b.Bytes())
	return err
}

// place assigns every member's header offset and returns the symdef member's
// total size.
func (w *Writer) place(syms []tocSymbol, strs []byte, wide bool) ([]uint64, int64) {
	word := int64(4)
	if wide {
		word = 8
	}
	// Payload: a size prefix, the ranlib array, a size prefix, the strings.
	payload := word + int64(len(syms))*word*2 + word + int64(len(strs))
	tocTotal := int64(HeaderSize) + int64(nameFieldSize(len(symdefName(wide, true)))) +
		roundUp64(payload, MemberAlign)

	off := int64(MagicSize) + tocTotal
	offsets := make([]uint64, len(w.inputs))
	for i, in := range w.inputs {
		offsets[i] = uint64(off)
		off += int64(HeaderSize) + int64(nameFieldSize(len(in.Name))) +
			roundUp64(int64(len(in.Data)), MemberAlign)
	}
	return offsets, tocTotal
}

// symdefName picks the table-of-contents member's name.
//
// Note that the size computation in place uses the sorted name unconditionally
// even when the table will be unsorted. The four names round to the same field
// width under nameFieldSize, so the choice cannot change any offset — but
// computing it from a name that is definitely long enough means a future name
// cannot silently shift the layout between the sizing pass and the write.
func symdefName(wide, sorted bool) string {
	switch {
	case wide && sorted:
		return Symdef64SortedName
	case wide:
		return Symdef64Name
	case sorted:
		return SymdefSortedName
	}
	return SymdefName
}

func (w *Writer) writeTOC(b *binio.Buf, syms []tocSymbol, strs []byte, wide, sorted bool, total int64) error {
	name := symdefName(wide, sorted)
	word := int64(4)
	if wide {
		word = 8
	}
	payload := word + int64(len(syms))*word*2 + word + int64(len(strs))

	start := b.Len()
	// The name field is sized for the sorted name so that an unsorted table,
	// whose name is shorter, still occupies the width place assumed.
	field := nameFieldSize(len(symdefName(wide, true)))
	if err := writeHeader(b, name, field, roundUp64(payload, MemberAlign), w.header()); err != nil {
		return err
	}

	put := func(v uint64) {
		if wide {
			b.U64(v)
		} else {
			b.U32(uint32(v))
		}
	}
	put(uint64(int64(len(syms)) * word * 2))
	for _, s := range syms {
		put(s.strx)
		put(s.off)
	}
	put(uint64(len(strs)))
	b.Raw(strs)
	b.Zero(int(roundUp64(payload, MemberAlign) - payload))

	if got := int64(b.Len() - start); got != total {
		return fmt.Errorf("ar: internal layout error: table of contents is %d bytes, expected %d",
			got, total)
	}
	return nil
}

// writeMember writes one member: header, padded name, padded contents.
func writeMember(b *binio.Buf, name string, data []byte, h Header) error {
	field := nameFieldSize(len(name))
	padded := roundUp64(int64(len(data)), MemberAlign)
	if err := writeHeader(b, name, field, padded, h); err != nil {
		return err
	}
	b.Raw(data)
	b.Zero(int(padded - int64(len(data))))
	return nil
}

// writeHeader writes an ar_hdr followed by the extended name.
//
// Every member goes through the extended form, whether or not its name would
// fit the 16-byte field. Two reasons: the variable-width name field is what
// absorbs the padding that keeps members 8-aligned, and a name containing a
// space is genuinely ambiguous in the fixed field — ar and ranlib historically
// disagreed about where such a name ends, which is the bug the sorted table's
// own name has to work around.
func writeHeader(b *binio.Buf, name string, field int, dataSize int64, h Header) error {
	if len(name) > field {
		return fmt.Errorf("ar: name %q does not fit its %d-byte field", name, field)
	}
	size := int64(field) + dataSize
	if size > 9999999999 {
		return fmt.Errorf("ar: member %q is %d bytes, too large for the size field", name, size)
	}

	pad := func(s string, n int) {
		if len(s) > n {
			s = s[:n]
		}
		b.String(s)
		for i := len(s); i < n; i++ {
			b.U8(' ')
		}
	}
	pad(fmt.Sprintf("%s%d", extPrefix, field), nameSize)
	pad(fmt.Sprintf("%d", h.Date), dateSize)
	pad(fmt.Sprintf("%d", h.UID), uidSize)
	pad(fmt.Sprintf("%d", h.GID), gidSize)
	pad(fmt.Sprintf("%o", h.Mode), modeSize)
	pad(fmt.Sprintf("%d", size), sizeSize)
	b.String(fmag)

	b.String(name)
	b.Zero(field - len(name))
	return nil
}

// header returns the metadata every member gets.
func (w *Writer) header() Header {
	mode := w.opts.Mode
	if mode == 0 {
		mode = 0644
	}
	if w.opts.Deterministic {
		return Header{Mode: mode}
	}
	t := w.opts.ModTime
	if t.IsZero() {
		t = time.Now()
	}
	return Header{Date: t.Unix(), UID: w.opts.UID, GID: w.opts.GID, Mode: mode}
}

// tocByteOrderOut returns the order the table of contents is written in.
//
// Every target this tree emits for is little-endian, and the table carries no
// field saying which order it used — the reader infers it from whether the
// size prefix is plausible. Writing anything else would be writing for a
// target that does not exist here.
func tocByteOrderOut() binary.ByteOrder { return binary.LittleEndian }