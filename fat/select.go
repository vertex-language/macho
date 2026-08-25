package fat

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// Find returns the slice that best serves the given cputype and cpusubtype.
//
// Selection is graded rather than first-match, which is what dyld does: it
// scores every slice against an ordered table and takes the best, so the order
// slices appear in the file does not decide which one runs.
//
// The grading here is a deliberate simplification of dyld's, covering the four
// architectures this tree targets:
//
//   - An exact subtype match always wins.
//   - A generic slice serves a specific request: arm64e falls back to arm64,
//     and x86_64h falls back to x86_64.
//   - The reverse never happens. A plain arm64 request must not be served an
//     arm64e slice, because arm64e is a different ptrauth ABI and not merely a
//     newer chip; an x86_64 request must not be served x86_64h, which requires
//     Haswell.
//   - Nothing matches across cputypes. arm64 and arm64_32 are different
//     cputypes, not two widths of one.
//
// Capability bits are masked off before comparing and preserved on the result.
// dyld additionally refuses an arm64e binary carrying ptrauth version 0 unless
// it is a platform binary; that is an execution policy rather than a selection
// rule, and it is not applied here.
func (f *File) Find(cpu macho.CPU, sub macho.SubCPU) (Arch, error) {
	best, bestGrade := Arch{}, 0
	for _, a := range f.Arches {
		if g := grade(cpu, sub, a); g > bestGrade {
			best, bestGrade = a, g
		}
	}
	if bestGrade == 0 {
		return Arch{}, fmt.Errorf("%w: no slice for %s in %s",
			macho.ErrNoMatchingSlice, macho.ArchName(cpu, sub), f.names())
	}
	return best, nil
}

// FindTarget is Find for a macho.Target. Platform and versions play no part:
// they live in load commands inside the slice, and the fat header carries
// neither.
func (f *File) FindTarget(t macho.Target) (Arch, error) { return f.Find(t.CPU, t.SubCPU) }

// FindName is Find for a toolchain arch name such as "arm64e" or "x86_64h".
func (f *File) FindName(name string) (Arch, error) {
	cpu, sub, ok := macho.ParseArch(name)
	if !ok {
		return Arch{}, fmt.Errorf("%w: unknown arch %q", macho.ErrUnsupportedCPU, name)
	}
	return f.Find(cpu, sub)
}

// Exact returns the slice whose cputype and cpusubtype match exactly, with no
// fallback. Use it when rewriting a fat file, where substituting a compatible
// slice for the requested one would silently change what the output contains.
func (f *File) Exact(cpu macho.CPU, sub macho.SubCPU) (Arch, error) {
	for _, a := range f.Arches {
		if a.CPU == cpu && a.SubCPU.Base() == sub.Base() {
			return a, nil
		}
	}
	return Arch{}, fmt.Errorf("%w: no %s slice in %s",
		macho.ErrNoMatchingSlice, macho.ArchName(cpu, sub), f.names())
}

// ExtentFor is the common path in one call: pick the best slice for a target
// and hand back a view ready for obj.NewFile or image.Read.
func (f *File) ExtentFor(t macho.Target) (binio.Extent, error) {
	a, err := f.FindTarget(t)
	if err != nil {
		return binio.Extent{}, err
	}
	return a.Extent()
}

// Names returns the arch name of every slice, in file order. It is what
// `lipo -info` prints.
func (f *File) Names() []string {
	out := make([]string, 0, len(f.Arches))
	for _, a := range f.Arches {
		out = append(out, a.Name())
	}
	return out
}

func (f *File) names() string {
	s := ""
	for i, n := range f.Names() {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return "[" + s + "]"
}

// grade scores one slice against a request. Zero means unusable; higher is
// better.
func grade(cpu macho.CPU, sub macho.SubCPU, a Arch) int {
	if a.CPU != cpu {
		return 0
	}
	want, have := sub.Base(), a.SubCPU.Base()
	if want == have {
		return 2
	}
	// A generic request served by a generic slice. ParseArch("arm64_32")
	// yields the V8 subtype while a slice may carry ALL, so the two forms of
	// "no particular chip" have to be interchangeable in both directions.
	if generic(cpu, want) && generic(cpu, have) {
		return 1
	}
	// A specific request falls back to a generic slice, never the reverse.
	if !generic(cpu, want) && generic(cpu, have) {
		return 1
	}
	return 0
}

// generic reports whether a subtype means "any implementation of this cputype"
// rather than naming a particular one.
func generic(cpu macho.CPU, sub macho.SubCPU) bool {
	switch cpu {
	case macho.CPU_TYPE_ARM64:
		return sub == macho.CPU_SUBTYPE_ARM64_ALL || sub == macho.CPU_SUBTYPE_ARM64_V8
	case macho.CPU_TYPE_ARM64_32:
		return sub == macho.CPU_SUBTYPE_ARM64_32_ALL || sub == macho.CPU_SUBTYPE_ARM64_32_V8
	case macho.CPU_TYPE_X86_64:
		return sub == macho.CPU_SUBTYPE_X86_64_ALL
	}
	return false
}