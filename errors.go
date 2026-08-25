package macho

import "errors"

var (
	// ErrNotMachO means the Mach-O magic was absent.
	ErrNotMachO = errors.New("macho: not a Mach-O file")

	// ErrShortHeader means the buffer was too short for the detection
	// function called. See MagicSize and KindPrefix.
	ErrShortHeader = errors.New("macho: buffer too short for header")

	// ErrFatFile means a universal file reached a thin reader.
	ErrFatFile = errors.New("macho: universal file passed to a thin reader")

	// ErrThinFile means a thin file reached a universal reader.
	ErrThinFile = errors.New("macho: thin file passed to a universal reader")

	// ErrFatOverlap means fat slices overlap each other or the fat header.
	// A crafted overlap is the standard way to make two tools disagree about
	// what a file contains, so it is an error rather than a warning.
	ErrFatOverlap = errors.New("macho: fat slices overlap")

	// ErrNoMatchingSlice means no slice in a universal file matched the
	// requested target.
	ErrNoMatchingSlice = errors.New("macho: no slice matches the target")

	// ErrInvalidTarget means a triple could not be parsed, or a Target failed
	// Valid.
	ErrInvalidTarget = errors.New("macho: invalid target")

	// ErrUnsupportedCPU means the cputype is not in the seeded table.
	ErrUnsupportedCPU = errors.New("macho: unsupported cputype")
)