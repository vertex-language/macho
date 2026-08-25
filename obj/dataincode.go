package obj

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
	"github.com/vertex-language/macho/internal/format"
)

// DataInCode marks a run of bytes inside an executable section that is data
// rather than instructions.
//
// A disassembler that ignores this table walks into a jump table and produces
// nonsense; more importantly for a linker, these runs must not be treated as
// code by anything that rewrites instructions, which is why the LOH pass and
// any future branch relaxation need to consult it.
type DataInCode struct {
	// Offset is from the start of the section the entry falls in — the
	// linker's view is a __TEXT-relative offset, but in an MH_OBJECT there is
	// one segment at address zero, so this is an offset in the object's
	// address space.
	Offset uint32
	Length uint16
	Kind   DICEKind

	// Sec is the section the run falls in, resolved, or nil if no section
	// covers the offset.
	Sec *Section
}

// DICEKind is the kind field of a data_in_code_entry.
type DICEKind uint16

const (
	DICEData          DICEKind = DICEKind(format.DICE_KIND_DATA)
	DICEJumpTable8    DICEKind = DICEKind(format.DICE_KIND_JUMP_TABLE8)
	DICEJumpTable16   DICEKind = DICEKind(format.DICE_KIND_JUMP_TABLE16)
	DICEJumpTable32   DICEKind = DICEKind(format.DICE_KIND_JUMP_TABLE32)
	DICEAbsJumpTable32 DICEKind = DICEKind(format.DICE_KIND_ABS_JUMP_TABLE32)
)

func (k DICEKind) String() string {
	switch k {
	case DICEData:
		return "data"
	case DICEJumpTable8:
		return "jump-table8"
	case DICEJumpTable16:
		return "jump-table16"
	case DICEJumpTable32:
		return "jump-table32"
	case DICEAbsJumpTable32:
		return "abs-jump-table32"
	}
	return fmt.Sprintf("dice-kind(0x%x)", uint16(k))
}

// DataInCode returns the LC_DATA_IN_CODE table, or nil if the file has none.
//
// Entries are in ascending offset order in every file this tree has seen, but
// nothing in the format requires it and this reader does not sort them.
func (f *File) DataInCode() ([]DataInCode, error) {
	data, err := f.linkeditBytes(macho.LC_DATA_IN_CODE)
	if err != nil || data == nil {
		return nil, err
	}
	if len(data)%format.DataInCodeEntrySize != 0 {
		return nil, fmt.Errorf("obj: data-in-code table is %d bytes, not a multiple of %d",
			len(data), format.DataInCodeEntrySize)
	}
	c := binio.NewCursor(data, f.Endian().Order())
	n := len(data) / format.DataInCodeEntrySize
	out := make([]DataInCode, 0, n)
	for i := 0; i < n; i++ {
		var e format.DataInCodeEntry
		if err := e.Decode(c); err != nil {
			return nil, err
		}
		d := DataInCode{Offset: e.Offset, Length: e.Length, Kind: DICEKind(e.Kind)}
		for _, s := range f.Sections {
			if s.Contains(uint64(e.Offset)) {
				d.Sec = s
				break
			}
		}
		out = append(out, d)
	}
	return out, c.Err()
}