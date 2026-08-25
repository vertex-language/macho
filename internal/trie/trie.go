// Package trie builds and walks the prefix trie that carries a Mach-O image's
// exported symbols.
//
// The same node format serves LC_DYLD_INFO_ONLY's export section and
// LC_DYLD_EXPORTS_TRIE; only where the offset comes from differs, so one
// implementation serves both.
//
// # Why building it needs a fixpoint
//
// A node names its children by absolute offset into the finished trie, and
// those offsets are ULEB128. Encoding a larger offset takes more bytes, which
// moves every node after it, which can make an offset larger. So offsets are
// assigned, sizes recomputed, and the pass repeated until nothing moves. It
// converges because a node only ever grows, and it terminates in two or three
// passes for any real symbol table — but it is a fixpoint, not a single pass,
// and writing it as one produces a trie whose child offsets are all slightly
// too small.
package trie

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vertex-language/macho/internal/binio"
)

// Export flag bits, from the export trie's own vocabulary rather than from
// nlist's.
const (
	ExportKindMask    uint64 = 0x03
	ExportKindRegular uint64 = 0x00
	ExportKindTLV     uint64 = 0x01
	ExportKindAbsolute uint64 = 0x02

	ExportWeakDefinition uint64 = 0x04
	ExportReexport       uint64 = 0x08
	ExportStubAndResolver uint64 = 0x10
)

// Export is one exported name.
type Export struct {
	Name  string
	Flags uint64

	// Address is the symbol's offset from the Mach-O header, not its virtual
	// address. dyld adds the slide, so an absolute address here would be
	// wrong by the image base in every process.
	Address uint64

	// Other is the resolver's offset for a stub-and-resolver export and the
	// library ordinal for a re-export. It is meaningless otherwise.
	Other uint64

	// ImportName is the name in the re-exporting library, when a re-export
	// renames. An empty string means the name is unchanged.
	ImportName string
}

// Build encodes a trie over the given exports.
//
// Duplicate names are an error rather than a last-one-wins: two exports of one
// name is a symbol table that already disagrees with itself, and the trie
// cannot represent the ambiguity.
func Build(exports []Export) ([]byte, error) {
	if len(exports) == 0 {
		return nil, nil
	}
	sorted := append([]Export(nil), exports...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Name == sorted[i-1].Name {
			return nil, fmt.Errorf("trie: %q exported twice", sorted[i].Name)
		}
	}

	root := &node{}
	for i := range sorted {
		if sorted[i].Name == "" {
			return nil, fmt.Errorf("trie: export with an empty name")
		}
		if err := root.insert(sorted[i].Name, &sorted[i]); err != nil {
			return nil, err
		}
	}

	order := root.flatten(nil)
	for _, n := range order {
		if err := n.encodeTerminal(); err != nil {
			return nil, err
		}
	}

	// The offset fixpoint. Ten rounds is far past what any real table needs;
	// exceeding it means the size computation and the encoder disagree, which
	// is a bug here rather than a property of the input.
	for round := 0; ; round++ {
		if round > 10 {
			return nil, fmt.Errorf("trie: offsets did not converge")
		}
		moved := false
		off := uint32(0)
		for _, n := range order {
			if n.offset != off {
				n.offset, moved = off, true
			}
			off += n.size()
		}
		if !moved {
			break
		}
	}

	b := binio.NewBuf(nil8{})
	for _, n := range order {
		n.encode(b)
	}
	if err := b.Err(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// nil8 is a byte order for a buffer that writes no multi-byte fields. Every
// number in a trie is ULEB128 and every string is bytes, so the order is never
// consulted — but Buf wants one, and passing binary.LittleEndian would imply a
// choice that does not exist.
type nil8 struct{}

func (nil8) Uint16([]byte) uint16       { return 0 }
func (nil8) Uint32([]byte) uint32       { return 0 }
func (nil8) Uint64([]byte) uint64       { return 0 }
func (nil8) PutUint16(b []byte, _ uint16) {}
func (nil8) PutUint32(b []byte, _ uint32) {}
func (nil8) PutUint64(b []byte, _ uint64) {}
func (nil8) String() string             { return "none" }

type node struct {
	terminal []byte // encoded payload, nil for a non-terminal node
	export   *Export
	edges    []edge
	offset   uint32
}

type edge struct {
	label string
	to    *node
}

// insert adds a name, splitting an existing edge where the two diverge.
func (n *node) insert(name string, e *Export) error {
	if name == "" {
		if n.export != nil {
			return fmt.Errorf("trie: %q exported twice", e.Name)
		}
		n.export = e
		return nil
	}
	for i := range n.edges {
		ed := &n.edges[i]
		common := commonPrefix(ed.label, name)
		if common == 0 {
			continue
		}
		if common < len(ed.label) {
			// Split: the existing edge becomes two, with a new interior node
			// at the point of divergence. A terminal node can have children —
			// _printf and _printf_l — so nothing about the split depends on
			// whether the shorter name was itself an export.
			mid := &node{edges: []edge{{label: ed.label[common:], to: ed.to}}}
			ed.label, ed.to = ed.label[:common], mid
		}
		return ed.to.insert(name[common:], e)
	}
	n.edges = append(n.edges, edge{label: name, to: &node{}})
	return n.edges[len(n.edges)-1].to.insert("", e)
}

func commonPrefix(a, b string) int {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return i
}

// flatten returns every node in a deterministic order: parents before
// children, edges in sorted label order. Determinism is the requirement — two
// runs over one symbol table must produce identical bytes — and parents-first
// keeps the root at offset zero, which dyld requires.
func (n *node) flatten(out []*node) []*node {
	out = append(out, n)
	sort.Slice(n.edges, func(i, j int) bool { return n.edges[i].label < n.edges[j].label })
	for _, e := range n.edges {
		out = e.to.flatten(out)
	}
	return out
}

func (n *node) encodeTerminal() error {
	if n.export == nil {
		return nil
	}
	e := n.export
	b := binio.NewBuf(nil8{})
	b.ULEB128(e.Flags)
	switch {
	case e.Flags&ExportReexport != 0:
		b.ULEB128(e.Other) // library ordinal
		b.CString(e.ImportName)
	case e.Flags&ExportStubAndResolver != 0:
		b.ULEB128(e.Address)
		b.ULEB128(e.Other) // resolver
	default:
		b.ULEB128(e.Address)
	}
	if err := b.Err(); err != nil {
		return err
	}
	n.terminal = b.Bytes()
	if len(n.terminal) > 0xff {
		// The terminal size is itself ULEB, so this is not a format limit —
		// but a payload this large means a name or an ordinal is nonsense.
		return fmt.Errorf("trie: %q has a %d-byte terminal payload", e.Name, len(n.terminal))
	}
	return nil
}

func (n *node) size() uint32 {
	sz := uint32(binio.ULEB128Size(uint64(len(n.terminal)))) + uint32(len(n.terminal))
	sz++ // child count, one byte
	for _, e := range n.edges {
		sz += uint32(len(e.label)) + 1
		sz += uint32(binio.ULEB128Size(uint64(e.to.offset)))
	}
	return sz
}

func (n *node) encode(b *binio.Buf) {
	b.ULEB128(uint64(len(n.terminal)))
	b.Raw(n.terminal)
	b.U8(uint8(len(n.edges)))
	for _, e := range n.edges {
		b.CString(e.label)
		b.ULEB128(uint64(e.to.offset))
	}
}

// TrimPrefix is a convenience for callers that strip a leading underscore
// before display. It is here so the trie's own notion of a name stays the
// on-disk one.
func TrimPrefix(name string) string { return strings.TrimPrefix(name, "_") }