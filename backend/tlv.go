package backend

import (
	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/image"
)

// Thread-local descriptors, and the one field in them that is not a
// pointer.
//
// A descriptor is three words — a thunk, a key, and an offset — and the
// object file writes a relocation into the third naming the variable's
// template. The name misleads: what belongs there is not the template's
// address but its distance from the start of the thread-local region,
// because dyld adds it to the base of the block it made for the calling
// thread. `otool -s __DATA __thread_vars` on a linked image shows 0, 4
// and 8 for three variables whose templates sit at 0, 4 and 8.
//
// So the field is a link-time constant. It takes no fixup, and treating
// it as a pointer produces one — a rebase that slides an offset by the
// image's load address, which the runtime then adds to the block base.
// The result is a wild pointer on the first read of a thread-local.

// tlvDataType reports whether a section holds thread-local templates.
func tlvDataType(t macho.SecType) bool {
	return t == macho.S_THREAD_LOCAL_REGULAR || t == macho.S_THREAD_LOCAL_ZEROFILL
}

// IsTLVTemplateRef reports whether a relocation is the offset field of a
// thread-local descriptor: it sits in a S_THREAD_LOCAL_VARIABLES section
// and names something in the template.
//
// Both halves matter. A descriptor's first word names the thunk, which
// is an ordinary imported pointer and has to stay one.
//
// The target is read the way Reloc.Target reads it, from the atom or the
// symbol. Which one a relocation carries is not a property of what it
// names but of how it survived merging: a reference to a local symbol
// becomes an atom reference, and `_counter$tlv$init` is local in every
// object clang emits. Asking only about symbols is asking about the
// external case alone, and that is the case this field is never in.
func IsTLVTemplateRef(atom *image.Atom, r image.Reloc) bool {
	if atom == nil || atom.Sec == nil {
		return false
	}
	if atom.Sec.Key.Type != macho.S_THREAD_LOCAL_VARIABLES {
		return false
	}
	target := tlvTargetAtom(r)
	return target != nil && target.Sec != nil && tlvDataType(target.Sec.Key.Type)
}

// TLVTemplateOffset is IsTLVTemplateRef plus the constant to write:
// the template's distance from the start of the thread-local region.
//
// The two are separate because their callers ask at different times.
// Scan runs before layout, when nothing has an address, and only needs
// to know whether to register a fixup. Apply runs after, and needs the
// number.
func TLVTemplateOffset(img *image.Image, atom *image.Atom, r image.Reloc) (uint64, bool) {
	if img == nil || !IsTLVTemplateRef(atom, r) {
		return 0, false
	}
	addr, err := r.Target()
	if err != nil {
		return 0, false
	}
	base, ok := tlvRegionBase(img)
	if !ok || addr < base {
		return 0, false
	}
	return addr - base, true
}

// tlvTargetAtom is the atom a relocation names, through either field.
func tlvTargetAtom(r image.Reloc) *image.Atom {
	if r.Atom != nil {
		return r.Atom
	}
	if r.Sym != nil {
		return r.Sym.Atom
	}
	return nil
}

// tlvRegionBase is the lowest address of the thread-local template
// sections, which is where the offsets in every descriptor are measured
// from.
//
// Lowest rather than the first found: dyld allocates one block for all
// of them together, and __thread_data and __thread_bss are two sections
// in it whose order the layout decides rather than this.
func tlvRegionBase(img *image.Image) (uint64, bool) {
	var base uint64
	found := false
	for _, seg := range img.Segments() {
		for _, sec := range seg.Sections() {
			if !tlvDataType(sec.Key.Type) {
				continue
			}
			if !found || sec.Addr < base {
				base, found = sec.Addr, true
			}
		}
	}
	return base, found
}
