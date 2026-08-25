// Package strtab builds the NUL-terminated string table that lives at the end
// of __LINKEDIT.
//
// The table is a flat run of bytes; a symbol names its string by a byte offset
// into it. Two properties make building one non-trivial.
//
// # Deduplication and tail sharing
//
// Identical strings collapse to one copy, which is obvious. Less obvious is
// that a string which is a suffix of another needs no bytes of its own at all:
// "_printf" and "printf" and "f" can be one seven-byte run plus a NUL, named
// by three different offsets into it. A real symbol table is mostly C and C++
// names with shared endings, so this is worth doing rather than a micro-
// optimization — and __LINKEDIT is hashed by the code signature, so every byte
// saved is a byte not hashed at launch.
//
// # Offsets are not known until the end
//
// A caller emitting nlist entries needs each symbol's string offset, but no
// offset can be assigned until every string is known, because sharing depends
// on the whole set. Add therefore returns a *Ref — a promise — and Offset
// resolves it only after Finish. Reading an offset early is a programming
// error and panics rather than returning a plausible-looking zero, because a
// zero offset is a legal value meaning the empty string, and a symbol table
// full of empty names is a bug that survives all the way to a linked image.
package strtab

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrNulInString means a string containing a NUL byte was added. Such a string
// cannot round-trip: a reader would stop at the interior NUL and see a
// different, shorter name.
var ErrNulInString = errors.New("strtab: string contains a NUL byte")

// Reserved offsets at the head of every table.
//
// ld64 emits a table beginning with a NUL and then a single space, so offset 0
// is the empty string and offset 1 is " ". Some tools assume that layout —
// notably, a zero n_strx is widely treated as "no name", and the space at 1 is
// what classic ld used for a symbol it wanted present but unnamed. Reproducing
// it costs three bytes and avoids finding out which tools depend on it the
// hard way.
const (
	// OffsetEmpty is the offset of the empty string.
	OffsetEmpty uint32 = 0

	// OffsetSpace is the offset of a single space.
	OffsetSpace uint32 = 1

	// prefix is the reserved head: "", then " ".
	prefixLen = 3
)

var prefix = [prefixLen]byte{0x00, ' ', 0x00}

// Builder accumulates strings and lays them out.
//
// The zero value is not usable; call New.
type Builder struct {
	byString map[string]*Ref
	refs     []*Ref // every distinct, non-pinned string, in insertion order
	buf      []byte
	done     bool
	err      error
}

// New returns an empty Builder whose table already contains the reserved head.
func New() *Builder {
	b := &Builder{byString: make(map[string]*Ref)}
	b.buf = append(b.buf, prefix[:]...)
	// Pin the two reserved strings so Add returns their fixed offsets rather
	// than emitting second copies.
	b.byString[""] = &Ref{b: b, s: "", off: OffsetEmpty, pinned: true}
	b.byString[" "] = &Ref{b: b, s: " ", off: OffsetSpace, pinned: true}
	return b
}

// Err returns the first error the builder hit, or nil.
//
// Add cannot return an error without making every call site check one, so
// errors latch here in the same style as binio. Check once before Bytes.
func (b *Builder) Err() error { return b.err }

func (b *Builder) fail(err error) {
	if b.err == nil {
		b.err = err
	}
}

// Add records s and returns a handle to its eventual offset.
//
// Adding the same string twice returns the same *Ref, so callers can use Add
// as a lookup and need not deduplicate themselves.
func (b *Builder) Add(s string) *Ref {
	if b.done {
		panic("strtab: Add after Finish")
	}
	if r, ok := b.byString[s]; ok {
		return r
	}
	if strings.IndexByte(s, 0) >= 0 {
		b.fail(fmt.Errorf("%w: %q", ErrNulInString, s))
		// Return a ref to the empty string so the caller gets a usable offset
		// and the error surfaces once, from Err.
		return b.byString[""]
	}
	r := &Ref{b: b, s: s}
	b.byString[s] = r
	b.refs = append(b.refs, r)
	return r
}

// Count returns the number of distinct strings added, excluding the two
// reserved ones.
func (b *Builder) Count() int { return len(b.refs) }

// Finish assigns every offset and builds the byte table.
//
// It is idempotent: calling it twice is a no-op rather than a second layout,
// so a Close path that may run more than once stays safe.
func (b *Builder) Finish() {
	if b.done {
		return
	}
	b.done = true
	if len(b.refs) == 0 {
		return
	}

	// Sort by reversed string. This groups strings that share a suffix, and
	// places a string immediately before the strings that extend it: "f"
	// reverses to "f", "_printf" reverses to "ftnirp_", and "f" < "ftnirp_".
	//
	// After the sort, s[i] can only be a suffix of s[i+1] — never of anything
	// further along that s[i+1] is not also a suffix of. That is what makes a
	// single backward pass sufficient.
	order := make([]*Ref, len(b.refs))
	copy(order, b.refs)
	sort.Slice(order, func(i, j int) bool {
		return lessReversed(order[i].s, order[j].s)
	})

	// Walk backwards so that a string's absorber is always already placed.
	// A chain — "f" into "tf" into "ntf" — resolves naturally: each link reads
	// the offset the previous iteration just assigned.
	for i := len(order) - 1; i >= 0; i-- {
		r := order[i]
		if i < len(order)-1 {
			next := order[i+1]
			if strings.HasSuffix(next.s, r.s) {
				// r lives inside next's bytes, at the point where the shared
				// tail begins. No bytes are emitted for r.
				r.off = next.off + uint32(len(next.s)-len(r.s))
				r.shared = true
				continue
			}
		}
		r.off = uint32(len(b.buf))
		b.buf = append(b.buf, r.s...)
		b.buf = append(b.buf, 0)
	}
}

// lessReversed compares two strings from their last byte backwards.
//
// It is the same ordering as sorting the reversed strings, without allocating
// the reversals.
func lessReversed(a, b string) bool {
	i, j := len(a)-1, len(b)-1
	for i >= 0 && j >= 0 {
		if a[i] != b[j] {
			return a[i] < b[j]
		}
		i--
		j--
	}
	// One is a suffix of the other; the shorter sorts first, which is what
	// puts a string immediately before the strings that extend it.
	return len(a) < len(b)
}

// Bytes returns the finished table. It calls Finish if the caller has not.
//
// The result aliases the builder's storage and must not be mutated.
func (b *Builder) Bytes() []byte {
	b.Finish()
	return b.buf
}

// Size returns the length of the finished table in bytes.
func (b *Builder) Size() int {
	b.Finish()
	return len(b.buf)
}

// Pad appends zero bytes until the table length is a multiple of align, which
// must be a positive power of two.
//
// __LINKEDIT tables are expected to be pointer-aligned so that whatever
// follows them starts aligned. Padding is safe to do after layout because it
// only extends the tail, and no offset points past the last string.
func (b *Builder) Pad(align int) {
	b.Finish()
	if align <= 1 {
		return
	}
	if align&(align-1) != 0 {
		b.fail(fmt.Errorf("strtab: Pad(%d): not a power of two", align))
		return
	}
	for len(b.buf)%align != 0 {
		b.buf = append(b.buf, 0)
	}
}

// Ref is a handle to a string's offset in the finished table.
//
// A Ref is stable across further Adds, which is the point: a caller can build
// its nlist entries holding Refs, then read every offset once at the end.
type Ref struct {
	b      *Builder
	s      string
	off    uint32
	shared bool
	pinned bool
}

// Offset returns the string's byte offset in the table.
//
// It panics if called before Finish. That is deliberate and not a
// defensiveness reflex: the zero value it would otherwise return is a legal
// offset meaning the empty string, so an early read produces a symbol table
// where every name is "" — a file that parses, links, and fails much later
// with no trace of the cause.
func (r *Ref) Offset() uint32 {
	if !r.b.done {
		panic("strtab: Ref.Offset before Finish")
	}
	return r.off
}

// String returns the string this Ref names.
func (r *Ref) String() string { return r.s }

// Shared reports whether this string was folded into another string's bytes
// rather than emitted on its own. It exists for diagnostics and for a future
// golden-file test that wants to assert sharing actually happened.
func (r *Ref) Shared() bool { return r.shared }