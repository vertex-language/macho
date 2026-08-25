// Package ar reads and writes BSD and Darwin ar archives.
//
// The ar format has never been standardized. Two variants matter here and only
// one is supported: the BSD form, where a name too long for the 16-byte field
// is stored in the member's data and announced as "#1/N", and its Darwin
// dialect, which adds a table of contents member named __.SYMDEF and aligns
// every member to 8 bytes. The SysV/GNU form — a "/" symbol table and a "//"
// string table — is detected and rejected rather than misparsed, because the
// two formats disagree about what a name beginning with "/" means and a reader
// that guesses produces plausible garbage.
//
// This package knows nothing about Mach-O. It does not import obj, and the
// writer takes each member's symbol list directly rather than extracting one,
// so an archive of anything at all can be built with it. A universal static
// library is a fat file whose slices are archives, so fat.Arch.Extent feeds
// NewFile directly and neither package needs to know about the other.
package ar

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrNotArchive means the "!<arch>\n" magic was absent.
	ErrNotArchive = errors.New("ar: not an archive")

	// ErrBadHeader means a member header was malformed: a missing trailing
	// magic, a size that is not a number, or a size that runs past the end of
	// the archive.
	ErrBadHeader = errors.New("ar: malformed member header")

	// ErrSysVArchive means a SysV/GNU-variant archive reached this reader.
	// The "/", "//", and "/SYM64/" members are a different format that shares
	// the same file magic, so this is a deliberate rejection rather than a
	// parse failure.
	ErrSysVArchive = errors.New("ar: SysV/GNU archive, deliberately unsupported")

	// ErrNoTOC means the archive has no __.SYMDEF member. Run ranlib, or
	// build it with this package's writer, which always emits one.
	ErrNoTOC = errors.New("ar: archive has no table of contents")

	// ErrBadTOC means the table of contents did not describe itself
	// consistently — a ranlib array or string table that overruns the member,
	// or an offset that names no member.
	ErrBadTOC = errors.New("ar: malformed table of contents")
)

// The file magic. Every archive begins with these eight bytes.
const (
	Magic     = "!<arch>\n"
	MagicSize = 8
)

// Fixed-width fields of struct ar_hdr. Every one is ASCII, space-padded on the
// right, and decimal — except mode, which is octal, as it is a stat mode.
const (
	nameSize  = 16
	dateSize  = 12
	uidSize   = 6
	gidSize   = 6
	modeSize  = 8
	sizeSize  = 10
	fmagSize  = 2

	// HeaderSize is the on-disk size of struct ar_hdr.
	HeaderSize = nameSize + dateSize + uidSize + gidSize + modeSize + sizeSize + fmagSize
)

// fmag terminates every member header. Its absence is the cheapest possible
// check that a header is where the previous member's size said it would be.
const fmag = "`\n"

// extPrefix introduces the BSD extended name form: "#1/N" in the name field,
// with N bytes of name stored at the front of the member's data and counted in
// its size.
const extPrefix = "#1/"

// MemberAlign is the boundary Darwin archives place every member on.
//
// The point is mappability: an archive member that is a Mach-O object can be
// parsed in place out of a mapped archive only if it starts aligned. Ordinary
// ar pads members to an even offset, which is not enough. Reaching 8 costs
// nothing, since the name field is variable-width under the extended form and
// can absorb the difference.
const MemberAlign = 8

// Table of contents member names.
//
// The sorted forms permit a binary search; the unsorted forms are ordered by
// member offset instead. A sorted table cannot express two members defining
// the same symbol — a search finds one and never learns of the other — so a
// writer that hits a duplicate must fall back to the unsorted form.
const (
	SymdefName         = "__.SYMDEF"
	SymdefSortedName   = "__.SYMDEF SORTED"
	Symdef64Name       = "__.SYMDEF_64"
	Symdef64SortedName = "__.SYMDEF_64 SORTED"
)

// IsSymdef reports whether name is one of the four table-of-contents names.
func IsSymdef(name string) bool {
	switch name {
	case SymdefName, SymdefSortedName, Symdef64Name, Symdef64SortedName:
		return true
	}
	return false
}

func symdefWide(name string) bool {
	return name == Symdef64Name || name == Symdef64SortedName
}

func symdefSorted(name string) bool {
	return name == SymdefSortedName || name == Symdef64SortedName
}

// Header is one member's decoded ar_hdr.
//
// Name is the raw 16-byte field with trailing blanks trimmed. Under the
// extended form it is the literal "#1/N", and the real name lives in the
// member's data; File resolves that and exposes only the resolved name.
type Header struct {
	Name string
	Date int64
	UID  int
	GID  int
	Mode uint32

	// Size is ar_size: the member's length including both the extended name
	// bytes at its front and any alignment padding at its end. It is not the
	// length of the member's contents; see Member.Size for that.
	Size int64
}

// decodeHeader parses a fixed 60-byte member header.
func decodeHeader(b []byte, off int64) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("%w: only %d bytes at offset %d", ErrBadHeader, len(b), off)
	}
	if string(b[HeaderSize-fmagSize:HeaderSize]) != fmag {
		return Header{}, fmt.Errorf("%w: no terminating magic at offset %d", ErrBadHeader, off)
	}

	f := func(start, n int) string { return string(b[start : start+n]) }
	pos := 0
	take := func(n int) string { s := f(pos, n); pos += n; return s }

	var (
		h   Header
		err error
	)
	h.Name = strings.TrimRight(take(nameSize), " ")
	if h.Date, err = decDefault(take(dateSize), 0); err != nil {
		return Header{}, fmt.Errorf("%w: bad date at offset %d: %v", ErrBadHeader, off, err)
	}
	uid, err := decDefault(take(uidSize), 0)
	if err != nil {
		return Header{}, fmt.Errorf("%w: bad uid at offset %d: %v", ErrBadHeader, off, err)
	}
	gid, err := decDefault(take(gidSize), 0)
	if err != nil {
		return Header{}, fmt.Errorf("%w: bad gid at offset %d: %v", ErrBadHeader, off, err)
	}
	h.UID, h.GID = int(uid), int(gid)

	// Mode is octal because it is a stat mode. Everything else in the header
	// is decimal, which is exactly the kind of inconsistency that survives
	// forty years of format history.
	mode, err := octDefault(take(modeSize), 0)
	if err != nil {
		return Header{}, fmt.Errorf("%w: bad mode at offset %d: %v", ErrBadHeader, off, err)
	}
	h.Mode = uint32(mode)

	if h.Size, err = decDefault(take(sizeSize), -1); err != nil || h.Size < 0 {
		return Header{}, fmt.Errorf("%w: bad size at offset %d", ErrBadHeader, off)
	}
	return h, nil
}

// decDefault parses a space-padded decimal field. An all-blank field is not an
// error: GNU archives leave date, uid, and gid empty on some members, and
// rejecting those would fail on files that every other tool reads.
func decDefault(s string, def int64) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

func octDefault(s string, def uint64) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	return strconv.ParseUint(s, 8, 32)
}

// extNameLen returns the length of the extended name a header announces, and
// whether it uses the extended form at all.
func extNameLen(name string) (int, bool) {
	if !strings.HasPrefix(name, extPrefix) {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(name[len(extPrefix):]))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// nameFieldSize returns the number of bytes the extended name field occupies
// for a name of the given length.
//
// The rounding is what keeps members 8-aligned. sizeof(ar_hdr) is 60, which is
// four short of a multiple of 8, so the name field carries those four bytes on
// top of a rounded name length. Together with the magic's 8 bytes and members
// whose data is padded to 8, every member header lands on a boundary.
func nameFieldSize(nameLen int) int {
	return roundUp(nameLen, MemberAlign) + (roundUp(HeaderSize, MemberAlign) - HeaderSize)
}

func roundUp(v, n int) int { return (v + n - 1) &^ (n - 1) }

func roundUp64(v, n int64) int64 { return (v + n - 1) &^ (n - 1) }