# macho

Read, write, and link Mach-O — relocatable objects, thin and universal (fat) binaries, static archives, and linked, code-signed executables — plus `.tbd` stub library resolution. arm64, arm64e, arm64_32, and x86_64 are the seeded targets.

## Install

```sh
go get github.com/vertex-language/macho
```

Architectures register themselves via blank import, so a build only pays for the backends it uses:

```go
import _ "github.com/vertex-language/macho/arm64" // registers AArch64
```

## Contents

- [Package map](#package-map)
- [Quick start](#quick-start)
  - [Identify a file](#identify-a-file)
  - [Read an object file](#read-an-object-file)
  - [Write an object file](#write-an-object-file)
  - [Universal (fat) binaries](#universal-fat-binaries)
  - [Resolve a system library (.tbd)](#resolve-a-system-library-tbd)
  - [Link an executable](#link-an-executable)
  - [Code-sign the result](#code-sign-the-result)
  - [Static archives](#static-archives)
- [How it's put together](#how-its-put-together)
- [Known limitations](#known-limitations)
- [License](#license)

## Package map

| Package | Purpose |
|---|---|
| `macho` | Shared vocabulary: magics, CPU/subtype, file types, load command IDs, section flags. No I/O, no dependencies. |
| `macho/obj` | Reads and writes `MH_OBJECT` — the relocatable objects a compiler emits and a linker consumes. |
| `macho/fat` | Reads and writes universal (fat) containers. Doesn't look inside slices — a slice can be an image, an object, or an archive. |
| `macho/ar` | Reads and writes BSD/Darwin `ar` archives, including the `__.SYMDEF` table of contents. |
| `macho/tbd` | Reads text-based stub libraries (`.tbd`, v1–v4) — how you link against system libraries that live only in the dyld shared cache. |
| `macho/image` | The linked-side output model: segments, sections, atoms, symbol table, in `open → sealed → frozen` phases. |
| `macho/backend` | The seam between the linker and the machine. Architectures implement this; `link` never imports one directly. |
| `macho/arm64` | AArch64 backend: relocations, stubs/GOT, range-extension thunks. |
| `macho/x86_64` | Intel 64 backend: relocations, stubs/GOT. |
| `macho/link` | The link pipeline itself — resolution, layout, relocation, emission. |
| `macho/codesign` | Ad-hoc and production (CMS) code signing, in place or into a buffer. |
| `macho/internal/*` | `binio` (bounds-checked cursor/buffer), `format` (the one definition of every wire struct), `strtab`, `trie`. Not part of the public API. |

## Quick start

### Identify a file

```go
package main

import (
	"fmt"
	"os"

	"github.com/vertex-language/macho"
)

func main() {
	data, err := os.ReadFile("/bin/ls")
	if err != nil {
		panic(err)
	}
	head := data[:macho.KindPrefix]

	switch {
	case macho.IsFat(head):
		fmt.Println("universal binary")
	case macho.Is(head):
		kind, err := macho.KindOf(head)
		if err != nil {
			panic(err)
		}
		fmt.Println("thin Mach-O:", kind)
	default:
		fmt.Println("not a Mach-O file")
	}
}
```

### Read an object file

```go
package main

import (
	"fmt"

	"github.com/vertex-language/macho/obj"
)

func main() {
	f, err := obj.Open("foo.o")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	fmt.Println("arch:", f.Arch())

	syms, err := f.Symbols()
	if err != nil {
		panic(err)
	}
	for _, s := range syms {
		if s.Ext() && s.Defined() {
			fmt.Printf("%-30s %#x\n", s.Name, s.Value)
		}
	}
}
```

### Write an object file

```go
package main

import (
	"os"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/obj"
)

func main() {
	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		panic(err)
	}

	f, err := os.Create("hello.o")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := obj.NewWriter(f, obj.Options{
		Target: target,
		Flags:  macho.MH_SUBSECTIONS_VIA_SYMBOLS,
		Build:  target.Build(), // required: an object with no platform makes every downstream linker guess
	})

	text := w.Section(obj.SectionHeader{
		Segment: macho.SEG_TEXT,
		Name:    macho.SECT_TEXT,
		Type:    macho.S_REGULAR,
		Attrs:   macho.S_ATTR_PURE_INSTRUCTIONS,
		Align:   4,
	})
	text.Write([]byte{0x1f, 0x20, 0x03, 0xd5}) // nop

	w.Symbol(obj.SymbolDef{
		Name:    "_main",
		Type:    macho.N_SECT,
		Ext:     true,
		Section: text,
	})

	if err := w.Close(); err != nil {
		panic(err)
	}
}
```

### Universal (fat) binaries

```go
package main

import (
	"fmt"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/fat"
	"github.com/vertex-language/macho/obj"
)

func main() {
	f, err := fat.Open("/usr/lib/libfoo.a")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	fmt.Println("slices:", f.Names()) // e.g. ["arm64", "arm64e", "x86_64"]

	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		panic(err)
	}

	// Graded selection, the way dyld does it: an exact subtype wins, a
	// generic slice can serve a specific request (arm64e falls back to
	// arm64), never the reverse.
	ext, err := f.ExtentFor(target)
	if err != nil {
		panic(err)
	}

	o, err := obj.NewFile(ext) // parsed in place, no copy out of the fat file
	if err != nil {
		panic(err)
	}
	fmt.Println("picked slice arch:", o.Arch())
}
```

### Resolve a system library (`.tbd`)

```go
package main

import (
	"fmt"
	"os"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/tbd"
)

func main() {
	data, err := os.ReadFile("libSystem.tbd")
	if err != nil {
		panic(err)
	}
	stub, err := tbd.Parse(data)
	if err != nil {
		panic(err)
	}

	target, _ := macho.ParseTarget("arm64-apple-macos14.0")
	for _, sym := range stub.Exports(target) {
		fmt.Println(sym.Name)
	}
	// libSystem defines almost nothing itself — follow re-exports for libc:
	for _, name := range stub.ReexportedLibraries(target) {
		fmt.Println("re-exports:", name)
	}
}
```

### Link an executable

```go
package main

import (
	"os"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/link"

	// Blank-import the architecture you're targeting; it registers itself
	// via init(). link never imports arm64 or x86_64 directly.
	_ "github.com/vertex-language/macho/arm64"
)

func mustRead(name string) []byte {
	b, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		panic(err)
	}

	l, err := link.New(target)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	if err := l.AddObject("main.o", mustRead("main.o")); err != nil {
		panic(err)
	}
	// Every program resolves against libSystem; a .tbd stub is what makes
	// that possible without the real dylib on disk.
	if err := l.AddStub("libSystem", mustRead("libSystem.tbd")); err != nil {
		panic(err)
	}

	l.Options().Output = link.OutputExecute
	l.DeadStrip(true)

	img, err := l.Link()
	if err != nil {
		panic(err)
	}

	out, err := img.Bytes()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("a.out", out, 0o755); err != nil {
		panic(err)
	}
}
```

### Code-sign the result

```go
package main

import "github.com/vertex-language/macho/codesign"

func main() {
	res, err := codesign.SignFile("a.out", codesign.Options{
		Identifier: "com.example.a",
		Hardened:   true, // sets CS_RUNTIME
	})
	if err != nil {
		panic(err)
	}
	println(res.Format, res.Identifier)
}
```

`SignFile` renames into place rather than overwriting — the kernel caches code signatures per vnode on Apple Silicon, and an in-place overwrite can leave a stale one behind.

### Static archives

```go
package main

import "github.com/vertex-language/macho/ar"

func main() {
	f, err := ar.Open("libfoo.a")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	m, err := f.Lookup("_foo") // walks the TOC rather than trusting a claimed sort
	if err != nil {
		panic(err)
	}
	data, err := m.Bytes()
	if err != nil {
		panic(err)
	}
	_ = data
}
```

## How it's put together

- **`macho` is the only vocabulary.** Every other package imports it; it imports nothing from the tree. `obj`, `fat`, `ar`, and `tbd` read and write on-disk formats in terms of it. `image`, `backend`, and `link` build the linked side on top. `codesign` and `internal/*` are the supporting cast.
- **Backends are pluggable, not switched on.** `link` never imports `arm64` or `x86_64`; it calls `backend.For(target)` and gets whatever registered itself via a blank import. Adding an architecture is one new package implementing `backend.Backend`, not a new case in an existing `switch`.
- **`image.Image` moves through phases and never backwards**: `open` (add sections and atoms, no address exists yet) → `sealed` (addresses and file offsets assigned, iterated to a fixpoint) → `frozen` (buffer exists, content can be written, nothing can be resized). Reading an address before it's assigned, or growing a section after layout, are phase errors instead of a file that silently corrupts itself.
- **Read and write are separate type families** in `obj`: a parsed `*File` is immutable, a `*Writer` under construction is a different type, and both go through `internal/format` — the one place every wire struct is defined, so a reader and writer of the same structure can't drift apart.

## Known limitations

- `macho`'s constants are a hand-seeded subset sufficient for arm64, arm64e, arm64_32, and x86_64 on Apple platforms — not exhaustive.
- `arm64`: no `backend.Relaxer` (the `LC_LINKER_OPTIMIZATION_HINT` adrp/add → adr/nop rewrite doesn't happen yet), and no relaxation of `GOT_LOAD` relocations that turn out to reference something in-image — every one gets a slot, at 8 bytes per symbol.
- `x86_64` doesn't implement `backend.Thunker` — its branches reach ±2 GiB, which nothing this tree produces exceeds.
- `backend`: no chained-fixup pointer format is chosen yet (`DYLD_CHAINED_PTR_64_OFFSET` vs. `..._ARM64E_USERLAND24`); nothing encodes a chain today.
- `link.OutputObject` (`ld -r`) is unimplemented — it needs relocation regeneration for a merged output, which doesn't exist yet.
- `tbd` handles stub versions 1–4. Version 5 (JSON) is detected and rejected outright rather than half-parsed.
- `ar` reads and writes the BSD/Darwin dialect only. SysV/GNU archives (`/` and `//` special members) are detected and rejected, not misparsed.
- `codesign.LoadIdentityPEM` reads PEM only; PKCS#12 (`.p12`) is out of scope — convert with `openssl pkcs12` first.

## License

MIT