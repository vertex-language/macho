package link

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vertex-language/macho"
)

// Sentinel errors. Anything a caller might reasonably branch on is here;
// everything else is a formatted error naming the input it came from.
var (
	// ErrNoLibSystem means the link had no dylib or stub input.
	//
	// Mach-O has no static link in the ELF sense. There is no libc.a to link
	// against — every program resolves against libSystem, which lives in the
	// dyld shared cache and is reachable only through a .tbd stub. A link
	// with no library input therefore cannot produce something dyld will
	// load, and failing here is better than emitting an image that dies at
	// launch with a message about a missing linker.
	ErrNoLibSystem = errors.New("link: no dylib or .tbd input; the result would not load")

	// ErrNoEntry means an executable's entry point could not be resolved.
	ErrNoEntry = errors.New("link: executable has no resolvable entry point")

	// ErrLayoutDivergence means the stub, thunk, and relaxation fixpoint did
	// not settle within MaxLayoutRounds. It is a backend bug, not an input
	// problem: the loop is monotonic and should converge in a few rounds.
	ErrLayoutDivergence = errors.New("link: layout did not converge")

	// ErrCPUMismatch means an input's cputype or cpusubtype disagrees with
	// the target.
	ErrCPUMismatch = errors.New("link: input architecture does not match the target")

	// ErrPlatformMismatch means an input's platform or minimum OS version is
	// incompatible with the target.
	ErrPlatformMismatch = errors.New("link: input platform does not match the target")

	// ErrNoInputs means nothing was added to link.
	ErrNoInputs = errors.New("link: no input files")

	// ErrUnimplemented marks a path this tree does not yet have. It exists so
	// that a caller can tell "not built yet" from "your inputs are wrong",
	// which matters a great deal while the pipeline is half-written.
	ErrUnimplemented = errors.New("link: unimplemented")
)

// UndefinedError names a symbol nothing defined, and everything known about
// where it was wanted.
//
// This is the diagnostic users see most, and the quality of a linker is
// largely the quality of this message. Naming the referencing file and offset
// is the difference between a fixable error and a bug report.
type UndefinedError struct {
	Name string

	// Refs are the places that referenced it, in the order they were found.
	// Held as a slice rather than one location because a symbol missing from
	// forty call sites is one mistake, and printing forty errors for it
	// buries the cause.
	Refs []Reference

	// From is the library the symbol was expected in, if a two-level lookup
	// suggested one. It is empty under a flat namespace, where nothing
	// records where a symbol should have come from — see NamespaceFlat.
	From string

	// Suggestions are names close enough to be plausible typos or mangling
	// mismatches.
	Suggestions []string
}

// Reference is one place a symbol was used.
type Reference struct {
	// Input is the file, and Atom the function or datum inside it.
	Input string
	Atom  string

	// Offset is from the start of the atom.
	Offset uint64
}

func (r Reference) String() string {
	s := r.Input
	if r.Atom != "" {
		s += "(" + r.Atom + ")"
	}
	if r.Offset != 0 {
		s += fmt.Sprintf("+0x%x", r.Offset)
	}
	return s
}

func (e *UndefinedError) Error() string {
	var b strings.Builder
	b.WriteString("link: undefined symbol " + e.Name)
	if e.From != "" {
		b.WriteString(", expected in " + e.From)
	}
	// Cap the reference list. A symbol referenced from thousands of sites is
	// one error, and dumping all of them makes the real message unreadable.
	const maxRefs = 3
	for i, r := range e.Refs {
		if i == 0 {
			b.WriteString("\n  referenced by ")
		} else if i < maxRefs {
			b.WriteString("\n                ")
		} else {
			fmt.Fprintf(&b, "\n                (and %d more)", len(e.Refs)-maxRefs)
			break
		}
		b.WriteString(r.String())
	}
	if len(e.Suggestions) > 0 {
		b.WriteString("\n  did you mean: " + strings.Join(e.Suggestions, ", "))
	}
	return b.String()
}

// DuplicateError means two inputs both defined a symbol strongly.
//
// Both sides are named, because knowing only one of them tells the user
// nothing they did not already know.
type DuplicateError struct {
	Name  string
	First Reference
	Again Reference
}

func (e *DuplicateError) Error() string {
	return fmt.Sprintf("link: duplicate symbol %s\n  defined in %s\n  and in     %s",
		e.Name, e.First, e.Again)
}

// OrdinalError means a two-level-namespace lookup found a symbol in a library
// other than the one that was expected.
//
// It is a distinct error from undefined because the fix is different: the
// symbol exists, and the link line names the wrong library or names them in
// the wrong order.
type OrdinalError struct {
	Name     string
	Expected string
	Found    string
	Ref      Reference
}

func (e *OrdinalError) Error() string {
	return fmt.Sprintf("link: %s is exported by %s, not by %s\n  referenced by %s",
		e.Name, e.Found, e.Expected, e.Ref)
}

// TooManyDylibsError means the link needs more library ordinals than n_desc
// can carry.
//
// The ordinal is eight bits with three values reserved, so 253 libraries is
// the ceiling. Overflowing it would wrap an ordinal onto a reserved value and
// silently turn a normal bind into a self, dynamic-lookup, or executable bind.
type TooManyDylibsError struct{ Count int }

func (e *TooManyDylibsError) Error() string {
	return fmt.Sprintf("link: %d libraries, but a two-level namespace ordinal holds at most %d",
		e.Count, macho.MAX_LIBRARY_ORDINAL)
}

// OverflowError wraps a backend range failure with the input it came from.
//
// The backend knows the field and the value; only link knows which object file
// contributed the instruction, and that is the half the user needs.
type OverflowError struct {
	Input string
	Err   error
}

func (e *OverflowError) Error() string {
	if e.Input == "" {
		return e.Err.Error()
	}
	return e.Input + ": " + e.Err.Error()
}

func (e *OverflowError) Unwrap() error { return e.Err }