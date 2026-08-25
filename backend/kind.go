package backend

// Kind is what a relocation asks the linker to arrange, with the architecture
// factored out.
//
// Every architecture spells these differently — ARM64_RELOC_GOT_LOAD_PAGE21
// and X86_64_RELOC_GOT_LOAD are the same request in two instruction sets — and
// link needs the request, not the spelling. Backend.Classify does the
// translation, and this is the vocabulary it translates into.
//
// The set is deliberately small. A Kind exists only where link has to do
// something different: reserve a slot, consider a thunk, expect a partner
// entry. Distinctions that only change which bits get written stay inside the
// backend, because link never writes bits.
type Kind uint8

const (
	// KindUnknown is an r_type the backend does not implement. link turns it
	// into ErrUnsupportedReloc rather than skipping the entry, because an
	// unapplied relocation leaves the compiler's placeholder in place and the
	// result is a wrong address that nothing downstream can detect.
	KindUnknown Kind = iota

	// KindAbsolute writes the target's address into a data word. This is the
	// only kind that produces a rebase or a bind, because it is the only one
	// whose written value depends on where the image lands at runtime.
	KindAbsolute

	// KindSubtractor is the first half of a difference between two addresses.
	// It writes nothing itself; its partner does, and link has already folded
	// the pair into one image.Reloc with Sub set by the time a backend sees
	// it.
	KindSubtractor

	// KindBranch is a direct call or jump whose displacement is encoded in the
	// instruction. It is the kind that can overflow its field, which is why it
	// is the kind a Thunker cares about, and the kind that binds to a stub
	// when its target is an import.
	KindBranch

	// KindSigned is a pc-relative reference to data — an x86_64 RIP-relative
	// operand, including the forms biased by 1, 2, or 4 bytes for an
	// instruction with a trailing immediate. The bias is a backend detail and
	// does not get its own Kind.
	KindSigned

	// KindPage is the page-address half of a two-instruction address
	// materialization: ADRP on arm64. It has no meaning without its
	// KindPageOff partner, but the two are separate relocations at separate
	// addresses and are not a pair in the SUBTRACTOR sense.
	KindPage

	// KindPageOff is the low-bits half: the ADD or LDR immediate.
	KindPageOff

	// KindGOTLoad is a reference through the GOT that the backend may be able
	// to relax into a direct reference when the target turns out to be defined
	// in this image. It needs a GOT slot unless it is relaxed away, which is
	// why the slot is reserved during Scan and the relaxation happens later.
	KindGOTLoad

	// KindGOT takes the address of a GOT slot rather than loading through it,
	// and can never be relaxed — the program wants the slot itself.
	KindGOT

	// KindTLV references a thread-local variable's descriptor, which the
	// runtime fills in per thread. The slot lives in __DATA,__thread_ptrs
	// rather than in the GOT.
	KindTLV

	// KindAddend carries a value in r_symbolnum and writes nothing. It exists
	// only on arm64, only immediately before the entry it modifies, and by the
	// time link builds an image.Reloc it has already been folded into that
	// entry's Addend — so a backend should not normally see one. It is in this
	// enumeration so that Classify can name it when reading an object.
	KindAddend

	// KindAuthPtr is an arm64e authenticated pointer: an absolute pointer that
	// is signed with a key and a discriminator rather than stored plainly.
	// Only a Signer backend produces one.
	KindAuthPtr
)

// NeedsGOT reports whether a relocation of this kind requires a GOT slot for
// its symbol.
func (k Kind) NeedsGOT() bool { return k == KindGOTLoad || k == KindGOT }

// NeedsTLV reports whether a relocation of this kind requires a thread-local
// variable slot.
func (k Kind) NeedsTLV() bool { return k == KindTLV }

// IsBranch reports whether a relocation of this kind is a branch, and
// therefore both a thunk candidate and a stub candidate.
func (k Kind) IsBranch() bool { return k == KindBranch }

// IsPointer reports whether a relocation of this kind writes a whole pointer
// into data, which is what makes it a rebase or bind site.
func (k Kind) IsPointer() bool { return k == KindAbsolute || k == KindAuthPtr }

// WritesField reports whether applying a relocation of this kind modifies the
// bytes at its address. KindAddend and KindSubtractor do not.
func (k Kind) WritesField() bool {
	return k != KindAddend && k != KindSubtractor && k != KindUnknown
}

func (k Kind) String() string {
	switch k {
	case KindAbsolute:
		return "absolute"
	case KindSubtractor:
		return "subtractor"
	case KindBranch:
		return "branch"
	case KindSigned:
		return "signed"
	case KindPage:
		return "page"
	case KindPageOff:
		return "pageoff"
	case KindGOTLoad:
		return "got-load"
	case KindGOT:
		return "got"
	case KindTLV:
		return "tlv"
	case KindAddend:
		return "addend"
	case KindAuthPtr:
		return "auth-pointer"
	}
	return "kind(?)"
}

// StubKind is which of the two stub strategies a backend uses.
type StubKind uint8

const (
	// StubNone means the backend generates no stubs.
	StubNone StubKind = iota

	// StubLazy is the classic three-part arrangement: __TEXT,__stubs jumps
	// through __DATA,__la_symbol_ptr, which initially points into
	// __TEXT,__stub_helper, which calls dyld_stub_binder to resolve the symbol
	// and overwrite the pointer. The first call to each symbol is slow and
	// every later one is a load and a jump.
	StubLazy

	// StubNonLazy is what a chained-fixups image uses: __TEXT,__stubs jumps
	// straight through a __got slot that dyld has already bound at load time.
	// There is no __stub_helper and no __la_symbol_ptr.
	//
	// This is the modern default and the one to implement first. Lazy binding
	// buys less than it used to — dyld binds the whole image up front anyway
	// under chained fixups — and it costs three sections, a bind opcode
	// stream, and a writable code path.
	StubNonLazy
)

func (k StubKind) String() string {
	switch k {
	case StubLazy:
		return "lazy"
	case StubNonLazy:
		return "non-lazy"
	}
	return "none"
}

// Lazy reports whether this strategy needs __stub_helper and
// __la_symbol_ptr.
func (k StubKind) Lazy() bool { return k == StubLazy }