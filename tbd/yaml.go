package tbd

import (
	"fmt"
	"strings"
)

// A minimal YAML reader, sufficient for .tbd and nothing else.
//
// The TBD format uses a narrow, regular subset of YAML: block mappings, block
// sequences whose items are mappings or scalars, and flow sequences of scalars
// that may wrap across lines. It uses no anchors, no aliases, no block
// scalars, no nested flow collections, and no explicit types. Everything
// outside that subset is a parse error here rather than a guess, because a
// stub library that silently loses half its exports produces a link that fails
// with an undefined symbol and no indication why.
//
// This exists so the tree keeps its zero-dependency promise. It is not a YAML
// implementation and must never be used as one.

type nodeKind uint8

const (
	kindScalar nodeKind = iota
	kindSeq
	kindMap
)

// node is one parsed YAML value.
type node struct {
	kind nodeKind
	str  string
	seq  []*node

	// A mapping keeps its keys in file order, in parallel slices. Order is not
	// semantically meaningful in TBD, but preserving it keeps error messages
	// pointing at the right place and makes a debug dump match the file.
	keys []string
	vals []*node

	line int
}

// get returns the value for a mapping key, or nil.
func (n *node) get(key string) *node {
	if n == nil || n.kind != kindMap {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.vals[i]
		}
	}
	return nil
}

// getAny returns the value for the first key present, which is how a key that
// was renamed between format versions is read once rather than at every use.
func (n *node) getAny(keys ...string) *node {
	for _, k := range keys {
		if v := n.get(k); v != nil {
			return v
		}
	}
	return nil
}

// text returns a scalar's value, or "" for anything else.
func (n *node) text() string {
	if n == nil || n.kind != kindScalar {
		return ""
	}
	return n.str
}

// list returns a sequence's scalar items.
//
// A missing key yields nil rather than an error: nearly every key in TBD is
// optional, and absent and empty mean the same thing for all of them.
func (n *node) list() []string {
	if n == nil {
		return nil
	}
	if n.kind == kindScalar {
		if n.str == "" {
			return nil
		}
		return []string{n.str}
	}
	if n.kind != kindSeq {
		return nil
	}
	out := make([]string, 0, len(n.seq))
	for _, it := range n.seq {
		if it.kind == kindScalar {
			out = append(out, it.str)
		}
	}
	return out
}

// items returns a sequence's elements, or nil.
func (n *node) items() []*node {
	if n == nil || n.kind != kindSeq {
		return nil
	}
	return n.seq
}

// yline is one significant line: comments stripped, blanks dropped, and any
// wrapped flow sequence already joined onto it.
type yline struct {
	indent int
	text   string
	num    int
}

// parseDocuments splits the input into YAML documents and parses each.
//
// The returned tags are the document tags — "!tapi-tbd-v3" and friends — which
// is how the format version is declared for everything before v4.
func parseDocuments(data []byte) (tags []string, docs []*node, err error) {
	lines, err := scanLines(data)
	if err != nil {
		return nil, nil, err
	}

	var (
		curTag   string
		curLines []yline
		started  bool
	)
	flush := func() error {
		if !started {
			return nil
		}
		var n *node
		if len(curLines) > 0 {
			ls := append([]yline(nil), curLines...)
			var idx int
			n, idx, err = parseBlock(ls, 0, ls[0].indent)
			if err != nil {
				return err
			}
			if idx != len(ls) {
				return fmt.Errorf("tbd: line %d: unexpected indentation", ls[idx].num)
			}
		}
		tags = append(tags, curTag)
		docs = append(docs, n)
		curTag, curLines, started = "", nil, false
		return nil
	}

	for _, l := range lines {
		switch {
		case l.indent == 0 && strings.HasPrefix(l.text, "---"):
			if err := flush(); err != nil {
				return nil, nil, err
			}
			started = true
			curTag = strings.TrimSpace(strings.TrimPrefix(l.text, "---"))
		case l.indent == 0 && l.text == "...":
			if err := flush(); err != nil {
				return nil, nil, err
			}
		default:
			// A v1 file has no document tag at all, so content before any
			// marker is a document rather than an error.
			started = true
			curLines = append(curLines, l)
		}
	}
	if err := flush(); err != nil {
		return nil, nil, err
	}
	return tags, docs, nil
}

// scanLines strips comments, drops blank lines, and joins wrapped flow
// sequences.
//
// The joining has to happen before anything looks at indentation. A symbol
// list that wraps is indented like a continuation, not like a nested block, so
// an indentation parser that sees the raw lines reads the second half of a
// symbol list as a new mapping and fails on the first name containing a colon.
func scanLines(data []byte) ([]yline, error) {
	raw := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var out []yline

	for i := 0; i < len(raw); i++ {
		s := raw[i]
		if strings.IndexByte(s, '\t') >= 0 && strings.TrimSpace(s) != "" {
			if lead := len(s) - len(strings.TrimLeft(s, " ")); strings.Contains(s[:lead+1], "\t") {
				return nil, fmt.Errorf("tbd: line %d: tab in indentation", i+1)
			}
		}
		indent := len(s) - len(strings.TrimLeft(s, " "))
		text, depth := scanText(s)
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		start := i + 1

		for depth > 0 {
			i++
			if i >= len(raw) {
				return nil, fmt.Errorf("tbd: line %d: unterminated flow sequence", start)
			}
			cont, d := scanText(raw[i])
			cont = strings.TrimSpace(cont)
			if strings.HasPrefix(cont, "---") || cont == "..." {
				return nil, fmt.Errorf("tbd: line %d: unterminated flow sequence", start)
			}
			if cont != "" {
				if text != "" && !strings.HasSuffix(text, ",") && !strings.HasSuffix(text, "[") {
					text += " "
				}
				text += cont
			}
			depth += d
		}
		out = append(out, yline{indent: indent, text: text, num: start})
	}
	return out, nil
}

// scanText strips a trailing comment and returns the line's net bracket depth,
// both computed in one pass so quote state is tracked once.
//
// Quote tracking is the whole point: a '#' inside a quoted symbol name is part
// of the name, and a '[' inside one does not open a sequence. Symbol names in
// real stub libraries contain '$', '.', and worse, and are quoted for exactly
// that reason.
func scanText(s string) (string, int) {
	var (
		inSingle, inDouble bool
		depth              int
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				// '' is an escaped quote inside a single-quoted scalar.
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
		case inDouble:
			if c == '\\' {
				i++
			} else if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == '#':
			if i == 0 || s[i-1] == ' ' {
				return s[:i], depth
			}
		}
	}
	return s, depth
}

func isSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

// parseBlock parses whatever block node begins at ls[i].
func parseBlock(ls []yline, i, indent int) (*node, int, error) {
	if i >= len(ls) {
		return nil, i, fmt.Errorf("tbd: unexpected end of document")
	}
	if isSeqItem(ls[i].text) {
		return parseSeq(ls, i, indent)
	}
	return parseMap(ls, i, indent)
}

func parseMap(ls []yline, i, indent int) (*node, int, error) {
	n := &node{kind: kindMap, line: ls[i].num}
	for i < len(ls) && ls[i].indent == indent && !isSeqItem(ls[i].text) {
		key, rest, ok := splitKey(ls[i].text)
		if !ok {
			return nil, i, fmt.Errorf("tbd: line %d: expected \"key: value\", got %q",
				ls[i].num, ls[i].text)
		}
		ln := ls[i].num
		i++

		var (
			v   *node
			err error
		)
		if rest == "" {
			// A block sequence under a key may be indented or may sit at the
			// key's own column; both appear in stub libraries in the wild.
			switch {
			case i < len(ls) && ls[i].indent > indent:
				v, i, err = parseBlock(ls, i, ls[i].indent)
			case i < len(ls) && ls[i].indent == indent && isSeqItem(ls[i].text):
				v, i, err = parseSeq(ls, i, indent)
			default:
				v = &node{kind: kindScalar, line: ln}
			}
		} else {
			v, err = parseInline(rest, ln)
		}
		if err != nil {
			return nil, i, err
		}
		n.keys = append(n.keys, key)
		n.vals = append(n.vals, v)
	}
	return n, i, nil
}

// parseSeq parses a block sequence.
//
// An item whose content begins on the dash line — "- targets: [...]" — starts a
// mapping at the content's column. That is rewritten in place into a synthetic
// line at that column so the ordinary mapping parser handles it; ls is a copy
// owned by parseDocuments, so the mutation is not visible to any caller.
func parseSeq(ls []yline, i, indent int) (*node, int, error) {
	n := &node{kind: kindSeq, line: ls[i].num}
	for i < len(ls) && ls[i].indent == indent && isSeqItem(ls[i].text) {
		body := strings.TrimSpace(ls[i].text[1:])
		col := indent + 1 + (len(ls[i].text[1:]) - len(strings.TrimLeft(ls[i].text[1:], " ")))
		ln := ls[i].num

		var (
			child *node
			err   error
		)
		switch {
		case body == "":
			if i+1 >= len(ls) || ls[i+1].indent <= indent {
				return nil, i, fmt.Errorf("tbd: line %d: sequence item has no value", ln)
			}
			child, i, err = parseBlock(ls, i+1, ls[i+1].indent)
		case isKeyLine(body):
			ls[i] = yline{indent: col, text: body, num: ln}
			child, i, err = parseMap(ls, i, col)
		default:
			child, err = parseInline(body, ln)
			i++
		}
		if err != nil {
			return nil, i, err
		}
		n.seq = append(n.seq, child)
	}
	return n, i, nil
}

// parseInline parses a value that appears on the same line as its key.
func parseInline(s string, line int) (*node, error) {
	if strings.HasPrefix(s, "[") {
		return parseFlowSeq(s, line)
	}
	return &node{kind: kindScalar, str: unquote(s), line: line}, nil
}

func parseFlowSeq(s string, line int) (*node, error) {
	if !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("tbd: line %d: unterminated flow sequence", line)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	n := &node{kind: kindSeq, line: line}
	if inner == "" {
		return n, nil
	}
	for _, part := range splitCommas(inner) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n.seq = append(n.seq, &node{kind: kindScalar, str: unquote(part), line: line})
	}
	return n, nil
}

// splitCommas splits on commas that are not inside quotes.
func splitCommas(s string) []string {
	var (
		out                []string
		start              int
		inSingle, inDouble bool
	)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case inSingle:
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
		case inDouble:
			if c == '\\' {
				i++
			} else if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ',':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// splitKey splits "key: value" at the first colon that is followed by a space
// or ends the line, outside quotes.
//
// The qualification matters: a symbol name may contain a colon, and a v2 uuid
// entry is literally "armv7: 0000-...". Requiring the space is what YAML does
// and what keeps those from being read as keys.
func splitKey(s string) (key, rest string, ok bool) {
	var inSingle, inDouble bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case inSingle:
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
		case inDouble:
			if c == '\\' {
				i++
			} else if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ':':
			if i+1 == len(s) {
				return unquote(strings.TrimSpace(s[:i])), "", true
			}
			if s[i+1] == ' ' {
				return unquote(strings.TrimSpace(s[:i])), strings.TrimSpace(s[i+2:]), true
			}
		}
	}
	return "", "", false
}

func isKeyLine(s string) bool {
	_, _, ok := splitKey(s)
	return ok
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	switch {
	case s[0] == '\'' && s[len(s)-1] == '\'':
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	case s[0] == '"' && s[len(s)-1] == '"':
		var b strings.Builder
		body := s[1 : len(s)-1]
		for i := 0; i < len(body); i++ {
			if body[i] == '\\' && i+1 < len(body) {
				i++
				switch body[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(body[i])
				}
				continue
			}
			b.WriteByte(body[i])
		}
		return b.String()
	}
	return s
}