package codesign

import (
	"fmt"
	"io"
	"strings"
)

// Verbosity levels mirroring codesigner -v / -vv / -vvv.
const (
	VerbosityOff = 0 // default: no extra output
	VerbosityV1  = 1 // -v:   arch, format, identifier, result
	VerbosityV2  = 2 // -vv:  CodeDirectory fields, flags, blob sizes, CDHash
	VerbosityV3  = 3 // -vvv: full Mach-O header, every load command, all page hashes, timing
)

// Logger is a levelled, nil-safe writer used throughout the codesign package.
// Every method is safe to call on a nil *Logger — they become no-ops.
type Logger struct {
	W         io.Writer
	Verbosity int
}

// NewLogger returns a Logger writing to w at the given verbosity level.
func NewLogger(w io.Writer, verbosity int) *Logger {
	return &Logger{W: w, Verbosity: verbosity}
}

func (l *Logger) emit(level int, format string, args ...interface{}) {
	if l == nil || l.Verbosity < level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(l.W, msg)
}

// V1 emits at verbosity ≥ 1 (-v).
func (l *Logger) V1(format string, args ...interface{}) { l.emit(1, format, args...) }

// V2 emits at verbosity ≥ 2 (-vv).
func (l *Logger) V2(format string, args ...interface{}) { l.emit(2, format, args...) }

// V3 emits at verbosity ≥ 3 (-vvv).
func (l *Logger) V3(format string, args ...interface{}) { l.emit(3, format, args...) }

// Section prints a titled divider at verbosity ≥ 3.
func (l *Logger) Section(title string) {
	if l == nil || l.Verbosity < 3 {
		return
	}
	fmt.Fprintf(l.W, "\n── %s ──\n", title)
}

// Active reports whether the logger would emit at the given level.
func (l *Logger) Active(level int) bool {
	return l != nil && l.Verbosity >= level
}