package macho

import (
	"fmt"
	"strings"
)

// A section specifier, as the assembler's .section directive spells one.
//
// Mach-O gives a section more identity than ELF does: a segment decides its
// load-time protection, a *type* decides what the linker may do with its
// contents, and a set of attributes decides the rest. All four are written on
// one line, comma-separated —
//
//	__TEXT,__objc_methname,cstring_literals
//	__DATA,__objc_selrefs,literal_pointers,no_dead_strip
//	__DATA,__objc_protolist,coalesced,no_dead_strip
//
// — and the three above are not decoration. cstring_literals is what lets the
// linker merge two images' copies of the same selector name; literal_pointers
// is what lets it merge two references to one selector; coalesced is why a
// protocol may be defined by every image that mentions it and survive once;
// and no_dead_strip is why a class the program never names by hand is still
// in the binary, because the runtime finds its work by walking sections and
// the linker cannot see that.
//
// This is the syntax as(1) accepts, which is why it is the syntax a compiler
// emits: the names below are the assembler's own, and a specifier that
// round-trips through this parser is one the platform's tools also read.

// A SectionSpec is a Mach-O section's full identity.
type SectionSpec struct {
	Segment string
	Section string
	Type    SecType
	Attrs   SecAttrs
}

// String renders the specifier the way it is written.
func (s SectionSpec) String() string {
	out := s.Segment + "," + s.Section
	if s.Type != S_REGULAR || s.Attrs != 0 {
		out += "," + secTypeSpelling(s.Type)
	}
	if names := attrSpellings(s.Attrs); len(names) > 0 {
		out += "," + strings.Join(names, "+")
	}
	return out
}

// LooksLikeSectionSpec reports whether a name is written as a Mach-O section
// specifier rather than as an ELF-style section name.
//
// The test is the comma. An ELF name has none — `.rodata`, `.debug_info` —
// and a Mach-O specifier always has at least one, because a section without
// its segment does not identify anything.
func LooksLikeSectionSpec(name string) bool {
	return strings.Contains(name, ",")
}

// ParseSectionSpec reads `segment,section[,type[,attribute[+attribute]…]]`.
//
// A missing type is S_REGULAR, which is what as(1) assumes. Whitespace around
// each field is ignored, since a compiler that builds the string from parts
// often leaves some.
//
// A fifth field is accepted and ignored: as(1) takes a stub size there for
// the symbol_stubs type, and nothing this parser's callers emit uses it.
func ParseSectionSpec(spec string) (SectionSpec, error) {
	parts := strings.Split(spec, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return SectionSpec{}, fmt.Errorf(
			"macho: %q is not a section specifier; it needs a segment and a section name", spec)
	}
	// A segment or section name lives in a sixteen-byte fixed field, and a
	// name that does not fit is silently truncated on the way out — which
	// produces two sections with one name, or none the linker recognizes.
	for _, p := range parts[:2] {
		if len(p) > 16 {
			return SectionSpec{}, fmt.Errorf(
				"macho: %q is %d bytes; a Mach-O segment or section name holds 16", p, len(p))
		}
	}
	out := SectionSpec{Segment: parts[0], Section: parts[1], Type: S_REGULAR}

	if len(parts) > 2 && parts[2] != "" {
		t, ok := secTypes[parts[2]]
		if !ok {
			return SectionSpec{}, fmt.Errorf("macho: unknown section type %q in %q", parts[2], spec)
		}
		out.Type = t
	}
	if len(parts) > 3 && parts[3] != "" {
		// as(1) joins attributes with '+', and a compiler that writes them
		// with commas instead is writing the same list; both are accepted,
		// since the field split above already handled the comma form.
		for _, field := range parts[3:] {
			for _, name := range strings.Split(field, "+") {
				name = strings.TrimSpace(name)
				if name == "" || name == "none" {
					continue
				}
				a, ok := secAttrs[name]
				if !ok {
					// The fifth field is a stub size for symbol_stubs, and
					// a number there is not an attribute anybody misspelled.
					if isNumber(name) {
						continue
					}
					return SectionSpec{}, fmt.Errorf(
						"macho: unknown section attribute %q in %q", name, spec)
				}
				out.Attrs |= a
			}
		}
	}
	return out, nil
}

func isNumber(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// secTypes is as(1)'s spelling of each section type.
var secTypes = map[string]SecType{
	"regular":                             S_REGULAR,
	"zerofill":                            S_ZEROFILL,
	"cstring_literals":                    S_CSTRING_LITERALS,
	"4byte_literals":                      S_4BYTE_LITERALS,
	"8byte_literals":                      S_8BYTE_LITERALS,
	"16byte_literals":                     S_16BYTE_LITERALS,
	"literal_pointers":                    S_LITERAL_POINTERS,
	"non_lazy_symbol_pointers":            S_NON_LAZY_SYMBOL_POINTERS,
	"lazy_symbol_pointers":                S_LAZY_SYMBOL_POINTERS,
	"symbol_stubs":                        S_SYMBOL_STUBS,
	"mod_init_funcs":                      S_MOD_INIT_FUNC_POINTERS,
	"mod_term_funcs":                      S_MOD_TERM_FUNC_POINTERS,
	"coalesced":                           S_COALESCED,
	"gb_zerofill":                         S_GB_ZEROFILL,
	"interposing":                         S_INTERPOSING,
	"dtrace_dof":                          S_DTRACE_DOF,
	"lazy_dylib_symbol_pointers":          S_LAZY_DYLIB_SYMBOL_POINTERS,
	"thread_local_regular":                S_THREAD_LOCAL_REGULAR,
	"thread_local_zerofill":               S_THREAD_LOCAL_ZEROFILL,
	"thread_local_variables":              S_THREAD_LOCAL_VARIABLES,
	"thread_local_variable_pointers":      S_THREAD_LOCAL_VARIABLE_POINTERS,
	"thread_local_init_function_pointers": S_THREAD_LOCAL_INIT_FUNCTION_POINTERS,
	"init_func_offsets":                   S_INIT_FUNC_OFFSETS,
}

// secAttrs is as(1)'s spelling of each section attribute.
var secAttrs = map[string]SecAttrs{
	"pure_instructions":   S_ATTR_PURE_INSTRUCTIONS,
	"no_toc":              S_ATTR_NO_TOC,
	"strip_static_syms":   S_ATTR_STRIP_STATIC_SYMS,
	"no_dead_strip":       S_ATTR_NO_DEAD_STRIP,
	"live_support":        S_ATTR_LIVE_SUPPORT,
	"self_modifying_code": S_ATTR_SELF_MODIFYING_CODE,
	"debug":               S_ATTR_DEBUG,
	"some_instructions":   S_ATTR_SOME_INSTRUCTIONS,
	"ext_reloc":           S_ATTR_EXT_RELOC,
	"loc_reloc":           S_ATTR_LOC_RELOC,
}

func secTypeSpelling(t SecType) string {
	for name, v := range secTypes {
		if v == t {
			return name
		}
	}
	return "regular"
}

// attrSpellings is the attribute names set in a, in a stable order so that
// String round-trips.
func attrSpellings(a SecAttrs) []string {
	order := []struct {
		name string
		bit  SecAttrs
	}{
		{"pure_instructions", S_ATTR_PURE_INSTRUCTIONS},
		{"no_toc", S_ATTR_NO_TOC},
		{"strip_static_syms", S_ATTR_STRIP_STATIC_SYMS},
		{"no_dead_strip", S_ATTR_NO_DEAD_STRIP},
		{"live_support", S_ATTR_LIVE_SUPPORT},
		{"self_modifying_code", S_ATTR_SELF_MODIFYING_CODE},
		{"debug", S_ATTR_DEBUG},
		{"some_instructions", S_ATTR_SOME_INSTRUCTIONS},
		{"ext_reloc", S_ATTR_EXT_RELOC},
		{"loc_reloc", S_ATTR_LOC_RELOC},
	}
	var out []string
	for _, o := range order {
		if a.Has(o.bit) {
			out = append(out, o.name)
		}
	}
	return out
}
