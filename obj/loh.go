package obj

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/internal/binio"
)

// LOHKind is the kind field of a linker optimization hint.
//
// The values are not in loader.h or any other Apple header — the encoding is
// defined only by the assembler that writes it and the linker that reads it.
// These match llvm's MCLOHType, which is what clang emits.
type LOHKind uint8

const (
	LOH_ARM64_ADRP_ADRP        LOHKind = 1 // adrp x, _a@PAGE ; adrp x, _b@PAGE
	LOH_ARM64_ADRP_LDR         LOHKind = 2 // adrp ; ldr @PAGEOFF
	LOH_ARM64_ADRP_ADD_LDR     LOHKind = 3 // adrp ; add @PAGEOFF ; ldr
	LOH_ARM64_ADRP_LDR_GOT_LDR LOHKind = 4 // adrp @GOTPAGE ; ldr @GOTPAGEOFF ; ldr
	LOH_ARM64_ADRP_ADD_STR     LOHKind = 5 // adrp ; add @PAGEOFF ; str
	LOH_ARM64_ADRP_LDR_GOT_STR LOHKind = 6 // adrp @GOTPAGE ; ldr @GOTPAGEOFF ; str
	LOH_ARM64_ADRP_ADD         LOHKind = 7 // adrp ; add @PAGEOFF   -> adr ; nop
	LOH_ARM64_ADRP_LDR_GOT     LOHKind = 8 // adrp @GOTPAGE ; ldr @GOTPAGEOFF
)

// Args returns the number of instruction addresses this kind carries, and
// whether the kind is one this reader knows.
//
// The count is redundant with the kind and is also stored in the file. They
// must agree: an entry whose declared count does not match its kind cannot be
// interpreted, and skipping it by its declared length would desynchronize the
// rest of the stream, since there is no framing between entries.
func (k LOHKind) Args() (int, bool) {
	switch k {
	case LOH_ARM64_ADRP_ADRP, LOH_ARM64_ADRP_LDR,
		LOH_ARM64_ADRP_ADD, LOH_ARM64_ADRP_LDR_GOT:
		return 2, true
	case LOH_ARM64_ADRP_ADD_LDR, LOH_ARM64_ADRP_LDR_GOT_LDR,
		LOH_ARM64_ADRP_ADD_STR, LOH_ARM64_ADRP_LDR_GOT_STR:
		return 3, true
	}
	return 0, false
}

func (k LOHKind) String() string {
	switch k {
	case LOH_ARM64_ADRP_ADRP:
		return "AdrpAdrp"
	case LOH_ARM64_ADRP_LDR:
		return "AdrpLdr"
	case LOH_ARM64_ADRP_ADD_LDR:
		return "AdrpAddLdr"
	case LOH_ARM64_ADRP_LDR_GOT_LDR:
		return "AdrpLdrGotLdr"
	case LOH_ARM64_ADRP_ADD_STR:
		return "AdrpAddStr"
	case LOH_ARM64_ADRP_LDR_GOT_STR:
		return "AdrpLdrGotStr"
	case LOH_ARM64_ADRP_ADD:
		return "AdrpAdd"
	case LOH_ARM64_ADRP_LDR_GOT:
		return "AdrpLdrGot"
	}
	return fmt.Sprintf("LOH(%d)", uint8(k))
}

// LOH is one linker optimization hint: a kind and the addresses of the
// instructions it applies to.
//
// Addrs are addresses in the object's address space, not section offsets and
// not file offsets. In an MH_OBJECT the single segment is at address zero, so
// an address is section addr plus offset; Sites resolves them.
type LOH struct {
	Kind  LOHKind
	Addrs []uint64
}

// LOHSite is one resolved instruction position.
type LOHSite struct {
	Sec    *Section
	Offset uint64
}

// Sites resolves a hint's addresses to (section, offset) pairs.
//
// An address that no section covers makes the whole hint unusable rather than
// partially usable: rewriting one instruction of a sequence and not the others
// produces code that computes the wrong address, so a hint is all-or-nothing.
func (f *File) Sites(h LOH) ([]LOHSite, bool) {
	out := make([]LOHSite, 0, len(h.Addrs))
	for _, a := range h.Addrs {
		var found *Section
		for _, s := range f.Sections {
			if s.Contains(a) {
				found = s
				break
			}
		}
		if found == nil {
			return nil, false
		}
		out = append(out, LOHSite{Sec: found, Offset: a - found.Addr})
	}
	return out, true
}

// OptimizationHints returns the LC_LINKER_OPTIMIZATION_HINT table.
//
// The payload is an unframed ULEB128 stream: kind, argument count, then that
// many addresses, repeated to the end of the declared size. There is no entry
// header and no length prefix, so a single misread value desynchronizes
// everything after it — which is why an unknown kind or a count that disagrees
// with its kind is an error here rather than a skipped entry.
//
// The table is arm64-only. Nothing emits it for x86_64, and a file that
// carries one for another architecture is reported rather than guessed at.
func (f *File) OptimizationHints() ([]LOH, error) {
	data, err := f.linkeditBytes(macho.LC_LINKER_OPTIMIZATION_HINT)
	if err != nil || data == nil {
		return nil, err
	}
	switch f.CPU() {
	case macho.CPU_TYPE_ARM64, macho.CPU_TYPE_ARM64_32:
	default:
		return nil, fmt.Errorf("obj: LC_LINKER_OPTIMIZATION_HINT in a %s file", f.Arch())
	}

	// Byte order is irrelevant to a ULEB stream, but the cursor wants one and
	// using the file's keeps error offsets consistent with everything else.
	c := binio.NewCursor(data, f.Endian().Order())

	var out []LOH
	for c.Remaining() > 0 {
		// The table is padded to a pointer boundary with zeros, and zero is
		// not a valid kind, so a zero here is the end rather than a corrupt
		// entry. Anything nonzero after this point must parse.
		if allZero(data[c.Pos():]) {
			break
		}

		kind := LOHKind(c.ULEB128())
		count := c.ULEB128()
		if err := c.Err(); err != nil {
			return nil, err
		}

		want, ok := kind.Args()
		if !ok {
			return nil, fmt.Errorf("obj: optimization hint at %d: unknown kind %d",
				c.Pos(), uint8(kind))
		}
		if count != uint64(want) {
			return nil, fmt.Errorf("obj: optimization hint %s at %d declares %d arguments, not %d",
				kind, c.Pos(), count, want)
		}

		h := LOH{Kind: kind, Addrs: make([]uint64, 0, want)}
		for i := 0; i < want; i++ {
			h.Addrs = append(h.Addrs, c.ULEB128())
		}
		if err := c.Err(); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, c.Err()
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}