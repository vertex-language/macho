package macho_test

import (
	"strings"
	"testing"

	"github.com/vertex-language/macho"
)

// Every specifier here is one a real compiler emits, and most of them are
// objv's: an Objective-C image is a dozen sections whose type and attributes
// are what make the runtime and the linker work.
func TestParseSectionSpec(t *testing.T) {
	for _, c := range []struct {
		spec  string
		seg   string
		sect  string
		typ   macho.SecType
		attrs macho.SecAttrs
	}{
		{"__DATA,__objc_data", "__DATA", "__objc_data", macho.S_REGULAR, 0},

		// cstring_literals is what lets the linker merge two images' copies
		// of the same selector name.
		{"__TEXT,__objc_methname,cstring_literals",
			"__TEXT", "__objc_methname", macho.S_CSTRING_LITERALS, 0},

		// literal_pointers merges two references to one selector;
		// no_dead_strip keeps a class the program never names by hand.
		{"__DATA,__objc_selrefs,literal_pointers,no_dead_strip",
			"__DATA", "__objc_selrefs", macho.S_LITERAL_POINTERS, macho.S_ATTR_NO_DEAD_STRIP},

		// coalesced is why every image that mentions a protocol may define
		// it and exactly one copy survives.
		{"__DATA,__objc_protolist,coalesced,no_dead_strip",
			"__DATA", "__objc_protolist", macho.S_COALESCED, macho.S_ATTR_NO_DEAD_STRIP},

		{"__DATA,__objc_classlist,regular,no_dead_strip",
			"__DATA", "__objc_classlist", macho.S_REGULAR, macho.S_ATTR_NO_DEAD_STRIP},

		// as(1) joins attributes with '+'; a compiler that writes them with
		// commas is saying the same thing.
		{"__TEXT,__text,regular,pure_instructions+some_instructions",
			"__TEXT", "__text", macho.S_REGULAR,
			macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS},
		{"__TEXT,__text,regular,pure_instructions,some_instructions",
			"__TEXT", "__text", macho.S_REGULAR,
			macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS},

		// Whitespace is ignored: a string built from parts often has some.
		{"__DATA , __const", "__DATA", "__const", macho.S_REGULAR, 0},

		// A stub size in the fifth field is as(1)'s and is not an attribute.
		{"__TEXT,__symbol_stub,symbol_stubs,none,12",
			"__TEXT", "__symbol_stub", macho.S_SYMBOL_STUBS, 0},

		{"__DATA,__thread_vars,thread_local_variables",
			"__DATA", "__thread_vars", macho.S_THREAD_LOCAL_VARIABLES, 0},
	} {
		got, err := macho.ParseSectionSpec(c.spec)
		if err != nil {
			t.Errorf("%q: %v", c.spec, err)
			continue
		}
		if got.Segment != c.seg || got.Section != c.sect {
			t.Errorf("%q: (%s,%s), want (%s,%s)", c.spec, got.Segment, got.Section, c.seg, c.sect)
		}
		if got.Type != c.typ {
			t.Errorf("%q: type = %v, want %v", c.spec, got.Type, c.typ)
		}
		if got.Attrs != c.attrs {
			t.Errorf("%q: attrs = %#x, want %#x", c.spec, uint32(got.Attrs), uint32(c.attrs))
		}
	}
}

func TestParseSectionSpecRejects(t *testing.T) {
	for _, c := range []struct{ spec, says string }{
		{"__DATA", "segment and a section"},
		{"", "segment and a section"},
		{"__DATA,", "segment and a section"},
		{"__DATA,__objc_data,nonsense", "unknown section type"},
		{"__DATA,__objc_data,regular,nonsense", "unknown section attribute"},
		// Sixteen bytes is the fixed field a name goes in, and a longer one
		// is truncated on the way out — into a name the linker does not know
		// or a second section with the same one.
		{"__DATA,__a_section_name_far_too_long", "16"},
	} {
		_, err := macho.ParseSectionSpec(c.spec)
		if err == nil {
			t.Errorf("%q was accepted", c.spec)
			continue
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%q: %v, want a message about %q", c.spec, err, c.says)
		}
	}
}

// A specifier round-trips, so what a writer records can be read back as the
// same section.
func TestSectionSpecString(t *testing.T) {
	for _, spec := range []string{
		"__DATA,__objc_data",
		"__TEXT,__objc_methname,cstring_literals",
		"__DATA,__objc_selrefs,literal_pointers,no_dead_strip",
		"__DATA,__objc_classlist,regular,no_dead_strip",
	} {
		s, err := macho.ParseSectionSpec(spec)
		if err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
		if got := s.String(); got != spec {
			t.Errorf("%q round-tripped as %q", spec, got)
		}
	}
}

func TestLooksLikeSectionSpec(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{"__DATA,__objc_data", true},
		{".rodata", false},
		{".debug_info", false},
		{".text", false},
	} {
		if got := macho.LooksLikeSectionSpec(c.name); got != c.want {
			t.Errorf("%q: %v, want %v", c.name, got, c.want)
		}
	}
}
