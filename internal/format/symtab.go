package format

import (
	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// Symtab is struct symtab_command.
type Symtab struct {
	Cmd     macho.LoadCmd
	CmdSize uint32
	SymOff  uint32
	NSyms   uint32
	StrOff  uint32
	StrSize uint32
}

// SymtabSize is the fixed size of struct symtab_command.
const SymtabSize = 24

func (s *Symtab) Decode(c *binio.Cursor) error {
	s.Cmd = macho.LoadCmd(c.U32())
	s.CmdSize = c.U32()
	s.SymOff = c.U32()
	s.NSyms = c.U32()
	s.StrOff = c.U32()
	s.StrSize = c.U32()
	return c.Err()
}

func (s *Symtab) Encode(b *binio.Buf) {
	b.U32(uint32(s.Cmd))
	b.U32(s.CmdSize)
	b.U32(s.SymOff)
	b.U32(s.NSyms)
	b.U32(s.StrOff)
	b.U32(s.StrSize)
}

// Dysymtab is struct dysymtab_command.
//
// The three index/count pairs at the front describe the three runs the symbol
// table must be sorted into — local, external defined, undefined. They are not
// advisory: dyld indexes into the table by these values, so a writer that
// emits symbols in a different order than it declares here produces an image
// that binds the wrong symbols.
type Dysymtab struct {
	Cmd     macho.LoadCmd
	CmdSize uint32

	ILocalSym  uint32
	NLocalSym  uint32
	IExtDefSym uint32
	NExtDefSym uint32
	IUndefSym  uint32
	NUndefSym  uint32

	TocOff uint32
	NToc   uint32

	ModTabOff uint32
	NModTab   uint32

	ExtRefSymOff uint32
	NExtRefSyms  uint32

	IndirectSymOff uint32
	NIndirectSyms  uint32

	ExtRelOff uint32
	NExtRel   uint32
	LocRelOff uint32
	NLocRel   uint32
}

// DysymtabSize is the fixed size of struct dysymtab_command: twenty 32-bit
// fields.
const DysymtabSize = 80

func (d *Dysymtab) Decode(c *binio.Cursor) error {
	d.Cmd = macho.LoadCmd(c.U32())
	d.CmdSize = c.U32()
	d.ILocalSym = c.U32()
	d.NLocalSym = c.U32()
	d.IExtDefSym = c.U32()
	d.NExtDefSym = c.U32()
	d.IUndefSym = c.U32()
	d.NUndefSym = c.U32()
	d.TocOff = c.U32()
	d.NToc = c.U32()
	d.ModTabOff = c.U32()
	d.NModTab = c.U32()
	d.ExtRefSymOff = c.U32()
	d.NExtRefSyms = c.U32()
	d.IndirectSymOff = c.U32()
	d.NIndirectSyms = c.U32()
	d.ExtRelOff = c.U32()
	d.NExtRel = c.U32()
	d.LocRelOff = c.U32()
	d.NLocRel = c.U32()
	return c.Err()
}

func (d *Dysymtab) Encode(b *binio.Buf) {
	b.U32(uint32(d.Cmd))
	b.U32(d.CmdSize)
	b.U32(d.ILocalSym)
	b.U32(d.NLocalSym)
	b.U32(d.IExtDefSym)
	b.U32(d.NExtDefSym)
	b.U32(d.IUndefSym)
	b.U32(d.NUndefSym)
	b.U32(d.TocOff)
	b.U32(d.NToc)
	b.U32(d.ModTabOff)
	b.U32(d.NModTab)
	b.U32(d.ExtRefSymOff)
	b.U32(d.NExtRefSyms)
	b.U32(d.IndirectSymOff)
	b.U32(d.NIndirectSyms)
	b.U32(d.ExtRelOff)
	b.U32(d.NExtRel)
	b.U32(d.LocRelOff)
	b.U32(d.NLocRel)
}

// Nlist is struct nlist / nlist_64.
//
// Desc is uint16 here even though the 32-bit form declares it int16. The field
// is a bit set in every use this tree makes of it — reference flags, weak
// bits, library ordinal — and treating it as signed makes the ordinal
// extraction sign-extend. The 32-bit and 64-bit forms occupy the same two
// bytes, so nothing is lost.
type Nlist struct {
	StrX  uint32
	Type  macho.SymType
	Sect  uint8
	Desc  macho.SymDesc
	Value uint64
}

const (
	nlistSize32 = 12
	nlistSize64 = 16
)

// NlistSize returns the on-disk size of one symbol table entry.
func NlistSize(w macho.Width) int {
	if w.Wide() {
		return nlistSize64
	}
	return nlistSize32
}

func (n *Nlist) Decode(c *binio.Cursor, w macho.Width) error {
	sz, err := ptrSize(w)
	if err != nil {
		return err
	}
	n.StrX = c.U32()
	n.Type = macho.SymType(c.U8())
	n.Sect = c.U8()
	n.Desc = macho.SymDesc(c.U16())
	n.Value = c.UintN(sz)
	return c.Err()
}

func (n *Nlist) Encode(b *binio.Buf, w macho.Width) {
	sz := mustPtrSize(w)
	b.U32(n.StrX)
	b.U8(uint8(n.Type))
	b.U8(n.Sect)
	b.U16(uint16(n.Desc))
	b.UintN(sz, n.Value)
}