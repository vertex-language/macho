package tbd

import (
	"fmt"

	"github.com/vertex-language/macho"
)

// Kind classifies an exported name.
type Kind uint8

const (
	Global Kind = iota
	Weak
	ThreadLocal
	ObjCClass
	ObjCIvar
	ObjCEHType
)

func (k Kind) String() string {
	switch k {
	case Global:
		return "global"
	case Weak:
		return "weak"
	case ThreadLocal:
		return "thread-local"
	case ObjCClass:
		return "objc-class"
	case ObjCIvar:
		return "objc-ivar"
	case ObjCEHType:
		return "objc-eh-type"
	}
	return "kind(?)"
}

// Symbol is one name a stub library exports.
//
// Name is always a real Mach-O symbol name, ready to be matched against an
// undefined symbol in an object file. For Objective-C entries that means the
// mangled form: the file lists a class as "NSString", and this reports
// "_OBJC_CLASS_$_NSString". Base keeps the unmangled name for diagnostics.
type Symbol struct {
	Name string
	Kind Kind

	// Base is the name as the file wrote it, normalized. For a Global or Weak
	// symbol it equals Name.
	Base string
}

func (s Symbol) String() string { return fmt.Sprintf("%s (%s)", s.Name, s.Kind) }

// Objective-C symbol prefixes.
//
// A class produces two symbols, not one: the class and its metaclass. A
// resolver that expands only the first leaves every "+alloc" send in the
// program unresolved, and the failure surfaces as an undefined
// _OBJC_METACLASS_$_Foo with nothing pointing back at the stub that should
// have provided it.
const (
	objcClassPrefix     = "_OBJC_CLASS_$_"
	objcMetaClassPrefix = "_OBJC_METACLASS_$_"
	objcIvarPrefix      = "_OBJC_IVAR_$_"
	objcEHTypePrefix    = "_OBJC_EHTYPE_$_"
)

// Exports returns every symbol the stub exports for the given target.
//
// The filtering is per section: a stub covering six targets lists a symbol
// once in whichever section covers the targets that have it, so a caller that
// takes the union across sections gets symbols that do not exist for the
// architecture it is linking.
//
// Objective-C entries are expanded into their mangled symbol names here rather
// than left to the caller. They are listed separately in the file because the
// mangling depends on the Objective-C ABI and keeping them unmangled lets one
// entry serve several architecture slices — which means the file's own form is
// never a symbol name, and a resolver matching on it finds nothing.
func (s *Stub) Exports(t macho.Target) []Symbol {
	return s.collect(s.exports, t)
}

// Reexported returns the symbols this stub re-exports for the target: names
// that resolve through this library's install name but are defined in another.
//
// They are kept separate from Exports because the two mean different things to
// a two-level-namespace link. A symbol found here still binds with this
// library's ordinal, but the definition lives elsewhere, so a diagnostic that
// names this library as the definer is misleading.
func (s *Stub) Reexported(t macho.Target) []Symbol {
	return s.collect(s.reexports, t)
}

// Undefineds returns the undefined symbols the stub declares for the target.
// The key applies only to flat-namespace libraries; it is empty otherwise.
func (s *Stub) Undefineds(t macho.Target) []Symbol {
	return s.collect(s.undefineds, t)
}

// ReexportedLibraries returns the install names this stub re-exports for the
// target. Following them is how libSystem resolves: it defines almost nothing
// itself and re-exports a dozen libraries under /usr/lib/system.
func (s *Stub) ReexportedLibraries(t macho.Target) []string {
	t, ok := s.resolve(t)
	if !ok {
		return nil
	}
	var out []string
	for _, g := range s.libs {
		if matchesAny(g.targets, t) {
			out = append(out, g.libs...)
		}
	}
	return dedupe(out)
}

// Clients returns the allowable clients for the target. A non-empty list means
// only those clients may link against the library; anything else is an error
// the linker is expected to raise.
func (s *Stub) Clients(t macho.Target) []string {
	t, ok := s.resolve(t)
	if !ok {
		return nil
	}
	var out []string
	for _, g := range s.clients {
		if matchesAny(g.targets, t) {
			out = append(out, g.clients...)
		}
	}
	return dedupe(out)
}

func (s *Stub) collect(secs []section, t macho.Target) []Symbol {
	t, ok := s.resolve(t)
	if !ok {
		return nil
	}
	var out []Symbol
	for _, sec := range secs {
		if !matchesAny(sec.targets, t) {
			continue
		}
		for _, n := range sec.symbols {
			out = append(out, Symbol{Name: n, Base: n, Kind: Global})
		}
		for _, n := range sec.weak {
			out = append(out, Symbol{Name: n, Base: n, Kind: Weak})
		}
		for _, n := range sec.threadLocal {
			out = append(out, Symbol{Name: n, Base: n, Kind: ThreadLocal})
		}
		for _, n := range sec.objcClasses {
			base := s.objcName(n)
			out = append(out,
				Symbol{Name: objcClassPrefix + base, Base: base, Kind: ObjCClass},
				Symbol{Name: objcMetaClassPrefix + base, Base: base, Kind: ObjCClass})
		}
		for _, n := range sec.objcEHTypes {
			base := s.objcName(n)
			out = append(out, Symbol{Name: objcEHTypePrefix + base, Base: base, Kind: ObjCEHType})
		}
		for _, n := range sec.objcIvars {
			base := s.objcName(n)
			out = append(out, Symbol{Name: objcIvarPrefix + base, Base: base, Kind: ObjCIvar})
		}
	}
	return out
}

// objcName normalizes an Objective-C name across format versions.
//
// v1 and v2 wrote these with a leading underscore — "_NSString" — and v3
// dropped it. Both name the same class, and the mangled symbol is the same
// either way, so the underscore is stripped before the prefix is applied
// rather than being carried into the symbol name, where it would produce
// "_OBJC_CLASS_$__NSString" and match nothing.
func (s *Stub) objcName(n string) string {
	if s.Version <= 2 && len(n) > 0 && n[0] == '_' {
		return n[1:]
	}
	return n
}

func matchesAny(ts []Target, want macho.Target) bool {
	for _, t := range ts {
		if t.Matches(want) {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}