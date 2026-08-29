package link

import (
	"fmt"
	"sort"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/backend"
	"github.com/vertex-language/macho/image"
)

// Ordering, synthetic registration, and the transition out of the open phase.
//
// This is the last step that may add sections and atoms freely, so everything
// the linker generates and sizes up front is created here: the GOT, the stubs,
// the thread-local pointers, and — for a lazy image — the lazy pointer table
// and its helper. Thunks are the exception and cannot be: how many exist
// depends on addresses, which is the fixpoint's job.
//
// order ends with Seal, which is what makes the atom set final and reserves
// the code signature slot.

// sectThunks holds range-extension veneers. It is a section of its own rather
// than a tail of __text so that a golden diff can see the thunks, and so that
// -order_file's rearrangement of __text cannot move a thunk away from what it
// was placed to reach.
const sectThunks = "__thunks"

func (l *Linker) order(img *image.Image) error {
	if err := l.registerSynthetics(img); err != nil {
		return err
	}
	if err := image.PrepareSynthetics(img); err != nil {
		return err
	}
	l.orderAtoms(img)

	// __LINKEDIT carries no sections, so nothing upstream ever asks for it by
	// asking for a section. It still has to exist before Seal, which is the
	// last point new segments may be created — and it has to be created last,
	// since assignAddresses places segments in Segments() order and reads the
	// address __LINKEDIT starts at off the cursor every other segment left
	// behind.
	if _, err := img.Segment(macho.SEG_LINKEDIT); err != nil {
		return err
	}

	if err := img.Seal(); err != nil {
		return err
	}
	// Seal assigns ordinals through OrderSections and discards its error,
	// which is the one place the >255 section limit is detected. Running it
	// again here is cheap and is where that error surfaces.
	return img.OrderSections()
}

// registerSynthetics creates the linker-generated tables.
//
// Order of registration is order of generation, and generation reads
// addresses, so nothing here may depend on another synthetic's *content* —
// only on its size, which Prepare fixes.
func (l *Linker) registerSynthetics(img *image.Image) error {
	st, ok := backend.AsStubber(l.be)
	if !ok {
		if l.reqs.StubCount() != 0 || l.reqs.GOTCount() != 0 {
			return fmt.Errorf("link: %s needs stubs or a GOT and its backend is not a Stubber",
				l.target.Arch())
		}
		return nil
	}
	shape := st.StubShape()

	// A non-lazy stub jumps through a __got slot, and neither backend's Scan
	// reserves one for a symbol it only branches to — Scan sees a branch and
	// calls reqs.Stub, nothing more. Reserving the slots here rather than in
	// each backend keeps the two backends' Scan honest about what they
	// actually observed, and keeps "a non-lazy stub is a GOT indirection"
	// stated once.
	if !shape.Kind.Lazy() {
		for _, sym := range l.reqs.StubSyms() {
			l.reqs.GOT(sym)
		}
	}

	got := &gotSynthetic{l: l, shape: st.GotShape()}
	if err := img.AddSynthetic(got); err != nil {
		return err
	}
	if err := img.AddSynthetic(&tlvSynthetic{l: l}); err != nil {
		return err
	}
	if l.reqs.StubCount() > 0 {
		s := &stubSynthetic{l: l, shape: shape, got: got}
		if shape.Kind.Lazy() {
			// The helper calls dyld_stub_binder through the GOT, so the
			// symbol has to have been interned and bound during resolution.
			// Nothing does that: resolve.go interns the entry point and -u
			// names and no more. Rather than inventing an import this late —
			// after ordinals are assigned — this is reported.
			bind := img.Symbols().Find("dyld_stub_binder")
			if bind == nil || bind.Class != image.ClassImport {
				return fmt.Errorf("%w: lazy stubs need dyld_stub_binder interned during resolve",
					ErrUnimplemented)
			}
			s.binder = bind
		}
		if err := img.AddSynthetic(s); err != nil {
			return err
		}
	}
	return nil
}

// orderAtoms applies -order_file.
//
// Named symbols move to the front of their section in the order listed;
// everything else keeps its relative order, which is extraction order and
// therefore deterministic. A name that resolves to nothing is ignored rather
// than reported: an order file is a performance hint written against one
// build and is routinely stale, and failing a link over it would be worse
// than the missed locality.
//
// The slice Section.Atoms returns aliases the section's own storage, so
// sorting it in place is the reordering. That is deliberate on image's part —
// there is no SetAtoms — but it is worth saying out loud, because it is the
// one place link mutates image's internals without going through a method.
func (l *Linker) orderAtoms(img *image.Image) {
	if len(l.opts.OrderFile) == 0 {
		return
	}
	table := img.Symbols()
	rank := make(map[*image.Atom]int, len(l.opts.OrderFile))
	for i, name := range l.opts.OrderFile {
		s := table.Find(name)
		if s == nil || s.Atom == nil || s.Atom.Coalesced {
			continue
		}
		if _, dup := rank[s.Atom]; dup {
			// Two names for one atom: the first listed decides.
			continue
		}
		rank[s.Atom] = i + 1
	}
	if len(rank) == 0 {
		return
	}
	for _, sec := range img.Sections() {
		atoms := sec.Atoms()
		sort.SliceStable(atoms, func(i, j int) bool {
			ri, rj := rank[atoms[i]], rank[atoms[j]]
			switch {
			case ri != 0 && rj != 0:
				return ri < rj
			case ri != 0:
				return true
			default:
				return false
			}
		})
	}
}

// --------------------------------------------------------------------------
// The synthetics.
//
// Each is one section holding one atom sized from a count Scan produced. One
// atom per table rather than one per slot: the slots are addressed as
// section base plus index times entry size — which is what backend.value
// computes — so there is nothing for a per-slot atom to buy, and a table of
// ten thousand atoms would be ten thousand layout decisions with one possible
// answer.
// --------------------------------------------------------------------------

// gotSynthetic is __DATA_CONST,__got.
type gotSynthetic struct {
	l     *Linker
	shape backend.GotShape

	sec  *image.Section
	src  *image.RawSource
	atom *image.Atom
}

func (g *gotSynthetic) SyntheticName() string { return g.shape.Name.String() }

func (g *gotSynthetic) Prepare(img *image.Image) error {
	n := g.l.reqs.GOTCount()
	if n == 0 {
		return nil
	}
	sec, err := img.Section(image.SectionKey{
		Name: g.shape.Name, Type: g.shape.Type, Attrs: g.shape.Attrs,
	})
	if err != nil {
		return err
	}
	g.sec, g.src = sec, image.NewRawSource(g.shape.Size(n))
	// reserved1 is this section's start in the shared indirect symbol table.
	// The GOT is first, stubs follow it, lazy pointers follow those; that
	// ordering is fixed here and linkedit.go must build the table in the same
	// order or every slot is misattributed.
	if err := sec.SetIndirectIndex(0); err != nil {
		return err
	}
	g.atom = &image.Atom{
		Name:   "<got>",
		Source: g.src,
		Align:  g.shape.Align,
	}
	if err := g.l.addSynthetic(sec, g.atom); err != nil {
		return err
	}

	// Every GOT slot is a pointer dyld must fix up at load time: a bind for a
	// slot targeting an import, since only dyld knows where that symbol
	// landed, and a rebase for one targeting something in this image, since
	// even a link-time-final address has to slide with ASLR. Generate writes
	// the bytes for the rebase case directly and leaves the bind case zero,
	// but writing bytes is not registering the fixup — nothing else does, and
	// an unregistered fixup is dyld reading whatever Generate left behind.
	entry := uint64(g.shape.EntrySize)
	for i, sym := range g.l.reqs.GOTSyms() {
		off := uint64(i) * entry
		if sym.Defined() {
			if err := g.l.reqs.AddRebase(backend.Rebase{Atom: g.atom, Offset: off}); err != nil {
				return err
			}
			continue
		}
		if err := g.l.reqs.AddBind(backend.Bind{
			Atom: g.atom, Offset: off, Sym: sym, Weak: sym.WeakRef,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (g *gotSynthetic) Generate(img *image.Image) error {
	if g.sec == nil {
		return nil
	}
	st, _ := backend.AsStubber(g.l.be)
	entry := int(g.shape.EntrySize)
	buf := make([]byte, g.shape.Size(g.l.reqs.GOTCount()))
	for i, sym := range g.l.reqs.GOTSyms() {
		// An import's slot is left zero. dyld writes it, and a plausible
		// address here would be indistinguishable from a bound one if the
		// fixup that should overwrite it were ever missing.
		var target uint64
		if sym.Bound {
			target = sym.Value
		}
		if err := st.WriteGotSlot(buf[i*entry:(i+1)*entry], target); err != nil {
			return err
		}
	}
	return g.src.Set(buf)
}

// tlvSynthetic is __DATA,__thread_ptrs: one descriptor pointer per
// thread-local symbol, written by the runtime rather than by the linker.
type tlvSynthetic struct {
	l   *Linker
	src *image.RawSource
}

func (t *tlvSynthetic) SyntheticName() string { return "__DATA,__thread_ptrs" }

func (t *tlvSynthetic) Prepare(img *image.Image) error {
	n := t.l.reqs.TLVCount()
	if n == 0 {
		return nil
	}
	word := uint32(t.l.be.WordSize())
	sec, err := img.Section(image.SectionKey{
		Name: macho.Sec(macho.SEG_DATA, macho.SECT_THREAD_PTRS),
		Type: macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
	})
	if err != nil {
		return err
	}
	t.src = image.NewRawSource(uint64(n) * uint64(word))
	return t.l.addSynthetic(sec, &image.Atom{
		Name: "<thread_ptrs>", Source: t.src, Align: word,
	})
}

func (t *tlvSynthetic) Generate(img *image.Image) error { return nil }

// stubSynthetic is __TEXT,__stubs and, when the strategy is lazy, the
// __DATA,__la_symbol_ptr table and the __TEXT,__stub_helper it initially
// points into.
type stubSynthetic struct {
	l     *Linker
	shape backend.StubShape
	got   *gotSynthetic

	stubs, ptrs, helper       *image.Section
	stubSrc, ptrSrc, helpSrc  *image.RawSource
	private                   *image.Atom
	privateSrc                *image.RawSource
	binder                    *image.Sym
}

func (s *stubSynthetic) SyntheticName() string { return s.shape.Name.String() }

func (s *stubSynthetic) Prepare(img *image.Image) error {
	n := s.l.reqs.StubCount()
	word := uint32(s.l.be.WordSize())

	sec, err := img.Section(image.SectionKey{
		Name: s.shape.Name, Type: s.shape.Type, Attrs: s.shape.Attrs,
	})
	if err != nil {
		return err
	}
	s.stubs, s.stubSrc = sec, image.NewRawSource(s.shape.Size(n))
	// reserved2 is one stub's size. Getting it wrong does not fail a link; it
	// makes every tool that walks the section pair the wrong symbol with the
	// wrong stub.
	if err := sec.SetStubSize(s.shape.EntrySize); err != nil {
		return err
	}
	if err := sec.SetIndirectIndex(uint32(s.l.reqs.GOTCount())); err != nil {
		return err
	}
	if err := s.l.addSynthetic(sec, &image.Atom{
		Name: "<stubs>", Source: s.stubSrc, Align: s.shape.Align,
	}); err != nil {
		return err
	}
	if !s.shape.Kind.Lazy() {
		return nil
	}

	ptrs, err := img.Section(image.SectionKey{
		Name: s.shape.PointerName, Type: s.shape.PointerType,
	})
	if err != nil {
		return err
	}
	s.ptrs, s.ptrSrc = ptrs, image.NewRawSource(uint64(n)*uint64(word))
	if err := ptrs.SetIndirectIndex(uint32(s.l.reqs.GOTCount() + n)); err != nil {
		return err
	}
	if err := s.l.addSynthetic(ptrs, &image.Atom{
		Name: "<la_symbol_ptr>", Source: s.ptrSrc, Align: word,
	}); err != nil {
		return err
	}

	helper, err := img.Section(image.SectionKey{
		Name:  s.shape.HelperName,
		Type:  macho.S_REGULAR,
		Attrs: macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
	})
	if err != nil {
		return err
	}
	s.helper, s.helpSrc = helper, image.NewRawSource(s.shape.HelperSize(n))
	if err := s.l.addSynthetic(helper, &image.Atom{
		Name: "<stub_helper>", Source: s.helpSrc, Align: s.shape.Align,
	}); err != nil {
		return err
	}

	// dyld_private is a word of scratch the helper hands to dyld_stub_binder
	// so it can identify the image. Its contents are never read by anything
	// this linker writes; its address is the whole point.
	data, err := img.Section(image.SectionKey{
		Name: macho.Sec(macho.SEG_DATA, macho.SECT_DATA), Type: macho.S_REGULAR,
	})
	if err != nil {
		return err
	}
	s.privateSrc = image.NewRawSource(uint64(word))
	s.private = &image.Atom{Name: "<dyld_private>", Source: s.privateSrc, Align: word}
	return s.l.addSynthetic(data, s.private)
}

func (s *stubSynthetic) Generate(img *image.Image) error {
	st, _ := backend.AsStubber(s.l.be)
	n := s.l.reqs.StubCount()
	word := uint64(s.l.be.WordSize())
	lazy := s.shape.Kind.Lazy()

	stubBuf := make([]byte, s.shape.Size(n))
	var ptrBuf, helpBuf []byte
	if lazy {
		ptrBuf = make([]byte, uint64(n)*word)
		helpBuf = make([]byte, s.shape.HelperSize(n))
		priv, err := s.private.Addr()
		if err != nil {
			return err
		}
		bindGot, err := s.gotSlot(s.binder)
		if err != nil {
			return err
		}
		if err := st.WriteStubHelperHeader(helpBuf, s.helper.Addr, priv, bindGot); err != nil {
			return err
		}
	}

	for i, sym := range s.l.reqs.StubSyms() {
		stubAddr := s.shape.Entry(s.stubs.Addr, i)

		var ptrAddr uint64
		if lazy {
			// The lazy bind stream is fixups.go's, and it does not exist. A
			// zero offset points every entry at the first opcode, which binds
			// the wrong symbol rather than failing — so it is reported here
			// instead of written.
			return fmt.Errorf("%w: lazy bind offsets come from fixups.go", ErrUnimplemented)
		} else {
			var err error
			if ptrAddr, err = s.gotSlot(sym); err != nil {
				return err
			}
		}
		lo := uint64(i) * uint64(s.shape.EntrySize)
		if err := st.WriteStub(stubBuf[lo:lo+uint64(s.shape.EntrySize)], stubAddr, ptrAddr); err != nil {
			return err
		}
	}

	if err := s.stubSrc.Set(stubBuf); err != nil {
		return err
	}
	if lazy {
		if err := s.ptrSrc.Set(ptrBuf); err != nil {
			return err
		}
		if err := s.helpSrc.Set(helpBuf); err != nil {
			return err
		}
	}
	return nil
}

// gotSlot returns the address of a symbol's GOT entry.
func (s *stubSynthetic) gotSlot(sym *image.Sym) (uint64, error) {
	i, ok := s.l.reqs.GOTIndex(sym)
	if !ok || s.got.sec == nil {
		return 0, fmt.Errorf("link: %s has a stub and no GOT slot", sym.Name)
	}
	return s.got.shape.Slot(s.got.sec.Addr, i), nil
}

// addSynthetic files a generated atom into a section and into the linker's
// flat list.
//
// Live and Root are set here rather than by the sweep, which has already run:
// a synthetic exists because something referenced the symbol it serves, so it
// is live by construction, and there is no relocation pointing at it for a
// reachability walk to follow.
func (l *Linker) addSynthetic(sec *image.Section, a *image.Atom) error {
	a.Live, a.Root = true, true
	if err := sec.AddAtom(a); err != nil {
		return err
	}
	l.atoms = append(l.atoms, a)
	return nil
}