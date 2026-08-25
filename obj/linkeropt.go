package obj

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/format"
)

// LinkerOptions returns the LC_LINKER_OPTION groups in file order.
//
// Each group is an argv fragment a compiler wants forwarded to the linker,
// most often ["-framework", "Foundation"] or ["-lz"]. The grouping matters:
// the two elements of a -framework option are one option, and flattening every
// group into one list loses which name belongs to which flag.
//
// The command appears only in MH_OBJECT files. It is how autolinking works —
// a header's #pragma comment(lib, ...) equivalent ends up here, and the linker
// discovers a dependency it was never told about on the command line. ld64
// silently ignores a group naming a library it cannot find, which is a
// behaviour link will have to decide about; this reader just reports them.
func (f *File) LinkerOptions() ([][]string, error) {
	cmds := f.FindAll(macho.LC_LINKER_OPTION)
	if len(cmds) == 0 {
		return nil, nil
	}
	out := make([][]string, 0, len(cmds))
	for _, cmd := range cmds {
		c := f.cursor(cmd)
		var lo format.LinkerOptionCmd
		if err := lo.Decode(c); err != nil {
			return nil, err
		}
		// The strings are NUL-terminated and variable length, so a count check
		// against a fixed element size is not available. One byte is the
		// minimum a string can occupy, which is enough to reject a count that
		// could not possibly fit.
		if _, ok := c.Count(uint64(lo.Count), 1, "linker option strings"); !ok {
			return nil, c.Err()
		}
		group := make([]string, 0, lo.Count)
		for i := uint32(0); i < lo.Count; i++ {
			s := c.CString()
			if err := c.Err(); err != nil {
				return nil, fmt.Errorf("obj: linker option %d: %w", i, err)
			}
			group = append(group, s)
		}
		out = append(out, group)
	}
	return out, nil
}