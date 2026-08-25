package link

import (
	"fmt"

	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
)

// Writing the output.
//
// Everything before this decided where bytes go; this is where they get
// written. The order is fixed by a dependency each way:
//
//	commit             sizes __LINKEDIT and freezes — the buffer now exists
//	thunks             veneer bytes, which need their target's final address
//	GenerateSynthetics stub and GOT bytes, same reason
//	writeAtoms         every atom's content into the buffer
//	applyAll           relocations, patched into the bytes just written
//
// Synthetics fill their own RawSource rather than writing to the image, so
// they have to run before writeAtoms copies sources into the buffer. Doing it
// the other way round emits a stub section full of zeros, which links, loads,
// and jumps to address zero on the first call to any import.

func (l *Linker) contents(img *image.Image) error {
	if err := l.commit(img); err != nil {
		return err
	}
	if err := l.writeThunks(img); err != nil {
		return err
	}
	if err := image.GenerateSynthetics(img); err != nil {
		return err
	}
	if err := l.writeAtoms(img); err != nil {
		return err
	}
	return l.applyAll(img)
}

// writeThunks fills in each veneer.
//
// The relocation that reaches a thunk was rewritten to name the thunk atom, so
// the thunk itself is the only thing left holding the original target — which
// is why thunkRec keeps the key rather than trusting the relocation.
func (l *Linker) writeThunks(img *image.Image) error {
	if len(l.thunkList) == 0 {
		return nil
	}
	th, ok := backend.AsThunker(l.be)
	if !ok {
		return fmt.Errorf("link: %d thunks placed and the backend is not a Thunker",
			len(l.thunkList))
	}
	for _, t := range l.thunkList {
		addr, err := t.atom.Addr()
		if err != nil {
			return err
		}
		target, err := thunkTarget(t.key)
		if err != nil {
			return err
		}
		buf := make([]byte, t.src.Size())
		if err := th.WriteThunk(buf, addr, target); err != nil {
			return &OverflowError{Input: "<linker-generated>", Err: err}
		}
		if err := t.src.Set(buf); err != nil {
			return err
		}
	}
	return nil
}

func thunkTarget(k thunkKey) (uint64, error) {
	switch {
	case k.atom != nil:
		return k.atom.Addr()
	case k.sym != nil:
		if !k.sym.Bound {
			return 0, fmt.Errorf("link: thunk to %s, which is unbound", k.sym.Name)
		}
		return k.sym.Value, nil
	}
	return 0, fmt.Errorf("link: thunk reaches neither a symbol nor an atom")
}

// writeAtoms copies every live atom's content into the output buffer.
//
// A zerofill atom is skipped rather than written as zeros: the buffer is
// already zero, and more to the point a zerofill section has no file offset to
// write at — asking for one is an error, which is the check that catches a
// zerofill section that was placed as though it had contents.
func (l *Linker) writeAtoms(img *image.Image) error {
	for _, sec := range img.Sections() {
		if sec.Zerofill() {
			continue
		}
		for _, a := range sec.LiveAtoms() {
			if a.Zerofill() || a.Size() == 0 {
				continue
			}
			data, err := a.Source.Bytes()
			if err != nil {
				return fmt.Errorf("link: %s: %w", atomWhere(a), err)
			}
			if uint64(len(data)) != a.Size() {
				// The size was used for layout rounds ago. A source that
				// produces a different number of bytes now has already
				// decided every following atom's address.
				return fmt.Errorf("link: %s is %d bytes, laid out as %d",
					atomWhere(a), len(data), a.Size())
			}
			off, err := a.FileOffset()
			if err != nil {
				return err
			}
			if err := img.WriteAt(off, data); err != nil {
				return fmt.Errorf("link: %s: %w", atomWhere(a), err)
			}
		}
	}
	return nil
}

// applyAll writes every relocation.
//
// A Site is built per atom rather than per relocation: it is a bounds-checked
// window onto the atom's bytes in the output buffer, so a relocation whose
// address is past the end of its own atom is reported against that atom
// instead of corrupting its neighbour.
func (l *Linker) applyAll(img *image.Image) error {
	for _, sec := range img.Sections() {
		if sec.Zerofill() {
			continue
		}
		for _, a := range sec.LiveAtoms() {
			if len(a.Relocs) == 0 || a.Zerofill() {
				continue
			}
			site, err := backend.SiteFor(img, a, l.reqs)
			if err != nil {
				return err
			}
			for _, r := range a.Relocs {
				if err := l.be.Apply(site, r); err != nil {
					// The backend knows the field and the value; only link
					// knows which object contributed the instruction, and
					// that is the half a user needs to fix it.
					return &OverflowError{Input: inputName(a), Err: err}
				}
			}
		}
	}
	return nil
}

func inputName(a *image.Atom) string {
	if a.Input != nil {
		return a.Input.Name
	}
	return "<linker-generated>"
}

func atomWhere(a *image.Atom) string {
	if a.Input != nil && a.Input.Name != "" {
		return a.Input.Name + "(" + a.String() + ")"
	}
	return a.String()
}