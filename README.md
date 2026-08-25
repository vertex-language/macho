# macho

Read, write, and link Mach-O — relocatable objects, universal binaries, static
libraries, executables, dylibs, and bundles (`MH_OBJECT`, `ar`, `MH_EXECUTE`,
`MH_DYLIB`, `MH_BUNDLE`) — plus code signing. `.tbd` stubs are read as link
inputs.

```go
go get github.com/vertex-language/macho
```

Zero dependencies. The decoders, encoders, the linker, and the CMS signer are
written from `loader.h`, `nlist.h`, `fat.h`, `fixup-chains.h`,
`compact_unwind_encoding.h`, `cs_blobs.h`, the TAPI documentation, and observed
`ld64` and `dyld` behaviour.

---

## Status

**The tree does not build.** Five concrete errors, listed under
[Does not build](#does-not-build). None is deep; all five are the kind that a
single `go build ./...` names for you, and they are here rather than left for it
because a reader deserves to know before they clone.

Nothing in this tree has been diffed against `clang`, `ld64`, `ld-prime`,
`libtool`, `llvm-readobj`, or `codesign`. There are no `_test.go` files
anywhere. Read the source before trusting a corner of it.

| Component | State |
| --- | --- |
| `macho` (constants, `Target`, `CPU`/`SubCPU`, detection) | in tree — hand-seeded subsets, enough for arm64 and x86_64 macOS |
| `internal/binio` | in tree — **one missing import**, see below |
| `internal/format` | in tree — every wire structure the rest of the tree uses |
| `internal/strtab` | in tree — dedup + tail sharing |
| `internal/trie` | in tree — export trie build, with the offset fixpoint |
| `obj` (`MH_OBJECT` read + write) | in tree, unverified |
| `fat` (universal read + write, 32- and 64-bit) | in tree, unverified |
| `ar` (BSD, Darwin sorted, `__.SYMDEF_64`) | in tree — **does not compile**, see below |
| `tbd` | v1–v4 in tree with a hand-written YAML subset reader; v5 (JSON) rejected |
| `image` | in tree — phased output model |
| `backend` | in tree — interface, registry, `Reqs`, `Site`, shapes |
| `arm64` | in tree — `Backend`, `Stubber`, `Thunker` |
| `x86_64` | in tree — `Backend`, `Stubber`; deliberately not a `Thunker` |
| `arm64e`, `arm64_32` | **not present** — `arm64.Config` exists to build them; nothing does |
| `link` | in tree — the whole pipeline, with undeclared fields, see below |
| `codesign` | in tree, standalone — ad-hoc and real CMS `SignedData` |
| Golden-file / fuzz tests | none |

### Does not build

1. **`internal/binio/cursor.go` uses `fmt` and does not import it.**
   `Cursor.UintN` calls `fmt.Errorf` on a bad width. Add `"fmt"`.

2. **`ar/write.go`'s `tocByteOrderOut` returns undefined types.** It is declared
   as `func tocByteOrderOut() binaryByteOrder { return littleEndian }`; neither
   identifier exists. It should return `binary.ByteOrder` and
   `binary.LittleEndian`.

3. **`ar` has no `IsArchive`.** `link/input.go`'s `AddFile` calls
   `ar.IsArchive(data)` to decide what a file is. Adding it is three lines
   against `Magic`.

4. **`link/resolve.go` uses `ar.Member` without importing `ar`**, and
   `resolution` has no `coalesced` field although `lost()` writes one. The
   struct also needs `coalesced map[definition]*image.Sym`.

5. **`link/split.go` references `macho.SEG_LD`, which does not exist.** `__LD`
   is the object-only segment compact unwind lives in; `split.go` declares its
   own `SEG_LD` constant and then reaches for the package's. Use the local one.

Beyond those, several `Linker` and `inputFile` fields are used before they are
declared. The full set the pipeline expects:

```go
// Linker
Warn        func(error)
atoms       []*image.Atom
folded      map[*image.Atom]*image.Atom
atomSection map[*image.Atom]image.SectionKey
thunks      map[thunkKey]*image.Atom
thunkList   []thunkRec
hints       []backend.Hint
hintsDone   bool
cu          []cuEntry
le          linkeditPlan
leAddr, leOff uint64
uuidOff     uint64
nLocal, nExtDef, nUndef uint32
symIndex    map[*image.Sym]int

// inputFile
split    *splitState
imgInput *image.Input
```

`backend.Reqs` needs `Hint`, `HintSite`, `SetHints`, and `Hints` for
`link/relax.go` to reach a `Relaxer`. `image.Section.AddAtom` and
`image.Image.Section` need to accept the sealed phase — thunks are created
during the layout fixpoint by construction, and the current
`require(PhaseOpen)` makes that impossible; the barrier that matters is
`Freeze`, not `Seal`.

---

## Scope

| In | Out |
| --- | --- |
| `MH_OBJECT` read + write | DWARF (`__DWARF` round-trips as opaque bytes) |
| Universal (fat) read + write, 32- and 64-bit offsets | `dSYM` generation — `dsymutil`'s job |
| `MH_EXECUTE` / `MH_DYLIB` / `MH_BUNDLE` write | Bitcode |
| `.tbd` stub libraries, v1 through v4 | `.tbd` v5 (JSON) — detected, rejected |
| `ar` in the BSD and Darwin flavors | SysV/GNU archives — detected, rejected |
| Symbol resolution, atom layout, relocation, `__LINKEDIT`, dyld metadata | The dyld shared cache |
| Chained fixups (`LC_DYLD_CHAINED_FIXUPS`) | Classic `LC_DYLD_INFO_ONLY` opcodes — **not implemented** |
| Compact unwind → `__unwind_info`, regular pages | Compressed second-level pages |
| Ad-hoc and real CMS code signing | Notarization; disassembly; any other container |
| Reading a `.dylib` for its exports | — **not implemented**; use `.tbd` |

---

## Design rules

These are the invariants the tree holds. Where one is not yet enforced by code,
[Known gaps](#known-gaps) says so.

**One definition of the wire format.** Every on-disk structure is defined
exactly once, in `internal/format`, with symmetric `Decode`/`Encode` and a size
function. `obj`, `fat`, and `link`'s emitter all go through it. No literal
structure size and no field offset appears anywhere else. The bug this removes
is a writer that emits 76 bytes for a structure the reader consumes 80 bytes
of — a file `otool` parses happily and `dyld` rejects at launch.

**Width is derived from CPU, never stored.** `macho.Width` is a *function* —
`CPU.Width()`, decided by the `CPU_ARCH_ABI64` bit, since `CPU_TYPE_X86_64` is
literally `CPU_TYPE_X86 | CPU_ARCH_ABI64`. There is no `Bits uint8`, no
`wide bool`, and no independently settable width field anywhere in an exported
API. `Width.Wide()` is total and never panics.

**`SubCPU` is a first-class axis, not a detail of `CPU`.** `arm64e` is a
`cpusubtype` of `CPU_TYPE_ARM64` carrying ptrauth ABI information in its high
capability byte. Every comparison masks with `SubCPU.Base()`; the capability
bits round-trip through fat headers unchanged.

**Byte order is per file and read from the magic.** Fat headers are the
exception the code makes explicit: always big-endian, regardless of the slices
inside, which is why `format.FatCursor` and `format.FatBuf` fix the order
rather than accepting one. Code-signing blobs are the other exception —
big-endian regardless of host or slice.

**Section identity is the `(segment, section)` pair.** `__DATA,__const` and
`__DATA_CONST,__const` are different sections and must never collapse. No API
accepts a bare section name. In `image` the key is wider still — name, type,
and attributes — because merging an `S_ZEROFILL` section into an `S_REGULAR`
one of the same name gives the result file bytes for content that has none.

**Section type and section attributes are distinct types.** One `uint32` on the
wire, `SecType` and `SecAttrs` in Go, packed only at the wire edge. A shared
`uint32` lets a type value leak into an attribute mask, which no compiler
catches.

**Relocations carry no addend.** Mach-O has no `r_addend`. The addend lives in
the instruction stream at `r_address`, or — on arm64 — travels in a preceding
`ARM64_RELOC_ADDEND` entry. Recovery is a psABI property and lives behind
`backend.Backend.Addend`.

**Paired relocations stay adjacent and in order.** `SUBTRACTOR` must be followed
by its `UNSIGNED`; `ADDEND` must precede its `BRANCH26`, `PAGE21`, or
`PAGEOFF12`. Nothing in either entry names the other, so `obj.Writer.Close`
**never sorts relocation entries**, and pairs are submitted through one call so
the invariant is unbreakable from outside. By the time `link` builds an
`image.Reloc` the pair has collapsed into one record with `Sub` set.

**Segments are explicit; sections are placed inside them.** ELF infers segments
from section flags. Mach-O does not — `__DATA_CONST` and `__DATA` hold sections
with identical flags and differ only in that one is made read-only after
fixups, so nothing can rediscover the grouping. `image.Segment` is a
first-class owner.

**Atoms, not sections, are the unit of layout.** Under
`MH_SUBSECTIONS_VIA_SYMBOLS` one symbol delimits one atom, and dead-stripping
and `-order_file` both operate at that granularity. `image.Atom` is
deliberately *not* split into read and write types the way `obj.Section` and
`obj.SectionBuilder` are: an atom read from an object and one the linker
generated are placed, relocated, swept, and emitted by the same code.

**Liveness and coalescing are two flags and stay two flags.** `Coalesced` means
an atom lost a weak-definition election — permanent, and independent of
`Live`. A coalesced atom can still be referenced and the reference is
redirected to the winner. Collapsing them was a real bug class in earlier
designs of this linker.

**Two-level namespace: an undefined symbol names a library.** The ordinal is
part of symbol identity in `image.SymbolTable`, not a field patched on at emit
time. Under `MH_TWOLEVEL`, `_malloc` from `libSystem` and `_malloc` from
`libfoo` are different symbols.

**Errors latch.** `binio.Cursor`, `binio.Buf`, `strtab.Builder`, `obj.Writer`,
`ar.Writer`, and `link.Linker` all accumulate the first failure and no-op
afterwards, so a decode or an emit pass is a straight run of calls with one
check at the end. Checking after every field is where bounds bugs hide.

**Counts are validated before allocation.** A declared element count that
cannot fit the remaining bytes is a `binio.CountError`, raised before anything
is sized. A header claiming four billion sections fails on the arithmetic, not
in `make`.

**The image has phases and never goes backwards.** `open → sealed → frozen`.
Reading an address before assignment yields zero, which is indistinguishable
from a legitimate address — `__PAGEZERO` really is at zero — so it is a phase
error instead. Growing a section after layout silently overlaps the next one.
Writing outside the buffer corrupts a neighbour. Each is caught at the point of
the mistake.

**Machine-specific knowledge lives behind `backend.Backend`.** `link` never
imports `arm64` or `x86_64`; it calls `backend.For`. A linker that reaches for
an architecture package directly grows a `switch cpu` in the middle of the
layout fixpoint, and every new architecture edits every such switch.

**The signature is part of the format, not a post-process.** An arm64 macOS
binary will not execute unsigned. `LC_CODE_SIGNATURE` must exist with zeroed
data *before* the CodeDirectory page hashes are computed, because those hashes
start at the Mach-O header and cover the load commands. `image` reserves the
slot during `Seal`, and the signature is the last registered `Finalizer`.

---

## Repo layout

```text
github.com/vertex-language/macho/
├── magic.go                # Magic, Width, Endian, MH_MAGIC/CIGAM(_64)
├── cpu.go                  # CPU, SubCPU, CPU_ARCH_ABI64, SubCPU.Base/Caps, ptrauth bits
├── filetype.go             # MH_OBJECT/EXECUTE/DYLIB/…, MH_* header flags
├── loadcmd.go              # LC_*, LC_REQ_DYLD, SegmentCmd(Width)
├── segment.go              # SG_*, Prot (VM_PROT_*), well-known segment names
├── section.go              # SecType (S_*), SecAttrs (S_ATTR_*), SecName pair
├── symbol.go               # N_STAB/N_TYPE/N_EXT, SymDesc bits, LibOrdinal
├── platform.go             # PLATFORM_*, Tool, Version (nibble-packed X.Y.Z)
├── reloc.go                # relocation_info bitfields, scattered form
├── reloc_arm64.go          # ARM64_RELOC_* + String()
├── reloc_x86_64.go         # X86_64_RELOC_* + String()
├── target.go               # Target, ParseTarget, triples
├── detect.go               # Is, IsFat, KindOf, TargetOf, MagicSize, KindPrefix
├── errors.go
│
├── internal/
│   ├── binio/              # binio.go buf.go cursor.go file.go leb128.go
│   ├── format/             # format.go header.go segment.go symtab.go
│   │                       #   linkedit.go dylib.go reloc.go fat.go
│   ├── strtab/             # strtab.go
│   └── trie/               # trie.go
│
├── obj/                    # MH_OBJECT — read and write
│   ├── file.go loadcmd.go section.go symbol.go reloc.go atom.go
│   ├── linkeropt.go dataincode.go loh.go
│   └── writer.go layout.go
│
├── fat/                    # file.go select.go write.go
├── ar/                     # ar.go read.go write.go
├── tbd/                    # tbd.go target.go symbol.go yaml.go
│
├── image/                  # image.go segment.go section.go atom.go
│                           #   symbol.go synthetic.go
│
├── backend/                # backend.go kind.go reqs.go shape.go site.go
├── arm64/                  # arm64.go insn.go stubs.go thunk.go
├── x86_64/                 # x86_64.go insn.go stubs.go
│
├── link/                   # one flat package
│   ├── link.go options.go errors.go input.go
│   ├── resolve.go split.go sweep.go merge.go unwind.go
│   ├── order.go assign.go relax.go apply.go
│   └── fixups.go linkedit.go emit.go
│
└── codesign/               # flat; standalone
    ├── codesign.go         # Size + Sign: the minimal linker-style ad-hoc path
    ├── sign.go             # SignFile/SignImage: the full codesign layout
    ├── macho.go            # its own thin Mach-O parser (see the note below)
    ├── blob.go blobs.go codedirectory.go
    ├── cms.go entitlements.go identity.go requirements.go
    └── logger.go
```

`link` is one flat package on purpose. `__LINKEDIT`'s contents depend on the
symbol table, which depends on dead-stripping, which depends on relocations,
which depend on addresses, which depend on the size of the load commands, which
depends on how many segments layout produced. Splitting that into `dyld/`,
`linkedit/`, and `unwind/` subpackages means either exporting most of it or
threading it all through parameters.

`codesign` parses Mach-O itself, in `codesign/macho.go`, rather than importing
`obj` or `image`. That is deliberate — it signs any finished Mach-O, including
one `ld64` produced — and it is also a second, independent Mach-O reader in a
tree whose first design rule is that the wire format is defined once. The
duplication is bounded (a header, `LC_SEGMENT_64`, `LC_CODE_SIGNATURE`) and it
is the price of the package standing alone.

---

## Package tour

### `macho` — identity and constants

Enumerations, flag constants, two relocation tables, and the `Target` type. No
I/O and no dependency on anything else in the tree.

`Version` is the nibble-packed `xxxx.yy.zz` encoding used by
`LC_BUILD_VERSION`'s `minos` and `sdk` and by dylib current/compatibility
versions. `ParseVersion("14.0")` and `String()` are the only conversions.

Constants are hand-seeded subsets. A third architecture needs its own
`reloc_<arch>.go` with a `String()` method — those two files are a template,
not yet generalized.

**There is no `fixups.go` and no `unwind.go` here.** The
`DYLD_CHAINED_PTR_*`, `DYLD_CHAINED_IMPORT_*`, and `UNWIND_*` constants exist
only as unexported blocks inside `link/fixups.go` and `link/unwind.go`, under a
banner saying so. They belong at this level; they are down there because the
encoders were written before the constant files were.

### `internal/binio` — bounded byte access

```go
c := binio.NewCursor(data, binary.LittleEndian)
v := c.U32()            // returns 0 and latches an error past the end
s := c.CString()
sub := c.Sub(24)        // an independent window; Fold merges its error back
if err := c.Err(); err != nil { … }
```

Bounds failures unwrap to `binio.ErrTruncated`; a declared count that cannot
fit is a `binio.CountError`, checked before anything is allocated.

`Buf` is the write side: order-aware appends, `Align`, `AlignFrom`, `Zero`, and
reservation patches (`Reserve32().Set(v)`). A `Ref` holds an offset rather than
a pointer, so it survives the buffer reallocating underneath it.

`File`/`Extent` bound reads against an `io.ReaderAt` of known size. `Extent` is
what lets `obj.NewFile` parse one slice of a fat file without copying it out,
and what `ar.Member.Extent` and `fat.Arch.Extent` hand back.

ULEB/SLEB128 live in `leb128.go` and are load-bearing here in a way they are not
in ELF: the export trie, `LC_FUNCTION_STARTS`, and
`LC_LINKER_OPTIMIZATION_HINT` are all ULEB-encoded.

### `internal/format` — the wire format

```go
func (s *Section) Decode(c *binio.Cursor, w macho.Width) error
func (s *Section) Encode(b *binio.Buf, w macho.Width)
func SectionSize(w macho.Width) int
```

Same pattern for `MachHeader`, `LoadCmdHeader`, `SegmentCmd`, `Symtab`,
`Dysymtab`, `Nlist`, `Reloc`, `ScatteredReloc`, `AnyReloc`, `LinkeditData`,
`DyldInfo`, `EntryPoint`, `UUID`, `SourceVersion`, `DataInCodeEntry`,
`BuildVersion`, `BuildToolVersion`, `VersionMin`, `Dylib`, `DylinkerCmd`,
`LinkerOptionCmd`, `FatHeader`, `FatArch`.

Width is never stored in a decoded struct; the caller passes it, having got it
from the file's magic or the target's CPU. The size functions are the only code
that knows which fields shrink — the trailing `Reserved3` exists only in the
64-bit `section_64`, and `SectionSize` is the only place in the tree that knows
it.

`DecodeHeader` is the entry point for opening a file: it verifies the magic
before trusting the byte order the magic implies, so a corrupt first word
cannot steer the rest of the decode.

### `internal/strtab` — string table builder

Deduplicating, with tail sharing: `"_printf"`, `"printf"`, and `"f"` are one
seven-byte run named by three offsets. `Add` returns a `*Ref`; `Offset()`
**panics** if read before `Finish`, because the zero it would otherwise return
is a legal offset meaning the empty string, and a symbol table full of empty
names survives all the way to a linked image. Index 0 is the empty string and
index 1 a single space, matching `ld64`.

### `internal/trie` — export trie

Builds the prefix trie shared by `LC_DYLD_INFO_ONLY`'s export section and
`LC_DYLD_EXPORTS_TRIE`. A node names its children by absolute ULEB offset, so
encoding a larger offset takes more bytes and moves every node after it:
`Build` assigns offsets, recomputes sizes, and repeats until nothing moves.
Writing it as a single pass produces a trie whose child offsets are all
slightly too small.

Only the build side exists. Walking a trie — which `link/read.go` would need to
read a real dylib's exports — is not written.

### `obj` — relocatable objects

Read and write are separate type families.

**Read.** `obj.File` is immutable after `Open`/`NewFile`. `NewFile` takes a
`binio.Extent`, so one slice of a universal file parses in place. `Section`
exposes `Data()`, `Open()`, `Relocs()`, `Atoms()`, `Type()`, `Attrs()`.
Symbols are decoded once and cached, so `*Symbol` pointer identity is stable —
`link` relies on that during resolution.

`Section.Atoms()` implements the `MH_SUBSECTIONS_VIA_SYMBOLS` split, including
the three rules that make it correct: an `N_ALT_ENTRY` symbol does not begin an
atom, symbols at one address are aliases of one atom rather than atoms of zero
size, and bytes before the first symbol form an anonymous leading atom rather
than being folded into the one that follows.

`LinkerOptions`, `DataInCode`, and `OptimizationHints` read the side tables.
The LOH stream is unframed ULEB — kind, count, then that many addresses — so a
single misread value desynchronizes everything after it, which is why an
unknown kind is an error rather than a skipped entry.

**Write.** `Writer.Close` orders symbols into the three runs the format
requires, fills `LC_DYSYMTAB`'s index and count pairs to match, places zerofill
sections last within the segment, builds `__LINKEDIT` with tail sharing, and
checks the section count against 255 and the file size against 4 GB — `n_sect`
is one byte and every `__LINKEDIT` offset is 32-bit even in a 64-bit object.

`Align` is in **bytes** on both sides of this package; the log2 form never
escapes the wire edge. `RelocSpec.Length` is not the same convention — it is
`macho.RelocLength`, whose documented meaning is a log2 byte width.

`LC_BUILD_VERSION` is required: `Options.Build` at its zero value is an error,
not a default.

### `fat` — universal files

`Slice(i)` hands back a `binio.Extent` that `obj.NewFile` or `ar.NewFile` can
consume without a copy.

Selection is graded rather than first-match, which is what `dyld` does: an
exact subtype wins, a generic slice serves a specific request (`arm64e` falls
back to `arm64`), and the reverse never happens — `arm64e` is a different
ptrauth ABI, not a newer chip.

Overlap detection is not optional: slices that overlap each other or the fat
header are `macho.ErrFatOverlap`, since a crafted overlap is the standard way to
make two tools disagree about a file's contents and both readings are
individually well-formed. `IsFat` also disambiguates against Java class files,
which share `0xCAFEBABE`; the test is `nfat_arch` against the class format's
minimum version, documented in `detect.go` rather than left as a mystery
constant.

The writer promotes to `FAT_MAGIC_64` automatically when a slice or offset
would exceed 4 GB, and orders slices by ascending alignment as `lipo` does.

### `ar` — archives

BSD and Darwin flavors. The Darwin table of contents is a first member named
`__.SYMDEF` or `__.SYMDEF SORTED`; the writer emits the sorted form and falls
back to the unsorted one when two members define the same symbol, because a
sorted table cannot express that — a binary search finds one and never learns
of the other. It auto-promotes to `__.SYMDEF_64 SORTED` past 4 GB.

Every member goes through the BSD `#1/NN` extended name form whether or not its
name would fit sixteen bytes: the variable-width name field is what absorbs the
padding that keeps members 8-aligned, so a member that is a Mach-O object can be
parsed in place out of a mapped archive.

SysV/GNU archives are detected and rejected (`ErrSysVArchive`) rather than
misparsed. `ar` does not import `obj` and has no idea what a Mach-O file is;
the caller supplies each member's symbol list.

### `tbd` — stub libraries

System libraries live in the dyld shared cache and are not in the SDK as Mach-O
files at all, so `.tbd` reading is mandatory to link an ordinary program.

v1 through v4 are handled. The YAML reader in `yaml.go` is a hand-written
subset parser — block mappings, block sequences, and flow sequences of scalars
that may wrap across lines — and everything outside that subset is an error
rather than a guess, because a stub that silently loses half its exports
produces an undefined-symbol error naming the symbol rather than the file.

Three things the format makes harder than it looks, all handled:

- v4 moved from `archs` plus a document-wide `platform` to `targets` tokens
  like `arm64-macos`, and filters every export list by them. Taking the union
  across sections yields symbols that do not exist for the architecture being
  linked.
- Objective-C entries are stored unmangled so one entry can serve several
  slices, which means the file's own form is never a symbol name. `Exports`
  expands them — and a class produces **two** symbols, the class and its
  metaclass; expanding only the first leaves every `+alloc` unresolved.
- v1 and v2 wrote ObjC names with a leading underscore and v3 dropped it. Both
  name the same class.

`Reexported` is kept separate from `Exports` because a re-exported symbol still
binds with this library's ordinal while being defined elsewhere.
`ReexportedLibraries` is how `libSystem` resolves at all: it defines almost
nothing itself.

v5 is JSON with a different key set. It is detected on the leading brace and
rejected with `ErrUnsupportedTBDVersion`.

### `image` — the output model

`Image` owns segments, output sections, the symbol table, and the output
buffer, moving through `open → sealed → frozen`.

`Segment` is explicit and ordered: `__PAGEZERO` (no file content), `__TEXT`
(file offset 0, covering the header and load commands — which is why
load-command size feeds back into layout), `__DATA_CONST`, `__DATA`,
`__LINKEDIT` (last, with the signature slot at its very end).

`Synthetic` is a two-step interface because of a circularity: a stub's *size* is
known before layout and its *content* is the address of something layout has
not placed. `Prepare` runs open, `Generate` runs frozen.

`Finalizer` runs after every other byte is final, in registration order, which
is load-bearing: the chained-fixup pass rewrites pointers, the UUID is computed
over the result, and the signature hashes everything including the UUID.

### `backend` — per-architecture behavior

```go
type Backend interface {
    CPU() macho.CPU
    SubCPU() macho.SubCPU
    Classify(typ uint8) Kind
    Scan(img *image.Image, reqs *Reqs) error
    Apply(s *Site, r image.Reloc) error
    Addend(content []byte, off uint64, r image.Reloc) (int64, bool)
    WordSize() int
}
```

`Stubber`, `Thunker`, `Relaxer`, and `Signer` are optional interfaces
discovered through `AsStubber` and friends. `Register` panics on a duplicate
`(cputype, cpusubtype)` pair and on a `WordSize` that disagrees with the CPU's
width — both are build-configuration mistakes that would otherwise surface as a
wrong file much later.

`SubCPU` is part of the interface and part of the registry key, and there is
deliberately **no** fallback from a specific subtype to a generic one. That is
the opposite of fat slice selection, and the difference is the point: a slice
is a whole image and a compatible one still runs, but a backend decides whether
pointers are signed.

The split from `x86_64` is worth noting: a CALL displacement is a signed 32-bit
field, so branches reach ±2 GiB and no `Thunker` is needed. On arm64 a
`BRANCH26` reaches ±128 MiB, so `arm64` **must** implement `Thunker` and the
thunk-growth fixpoint is not optional.

`Site` is one atom's output bytes with the address they will occupy. Every
write is bounds-checked against the atom, so a relocation past the end of its
own atom is an error naming the atom and its input rather than a corrupted
neighbour.

### `link` — the pipeline

`Linker.Link()` is a fixed sequence over one `*image.Image`:

```
resolve   symbols, archive fixpoint, weak defs, library ordinals
split     atoms; literals by content; __compact_unwind; __eh_frame CIE/FDE
sweep     -dead_strip, at atom granularity
check     undefined symbols
unwind    consume __compact_unwind, register __TEXT,__unwind_info
merge     literal dedup, atoms into output sections, -sectcreate
scan      backend: GOT/stub/TLV slots, rebase and bind sites
order     synthetics, -order_file, Seal
layout    the fixpoint: addresses, load-command size, thunks, relaxation
fixups    the chained-fixup blob, plus a Finalizer to thread the chains
linkedit  symtab, strtab, indirect symbols, export trie, function starts, DICE
contents  size __LINKEDIT, Freeze, generate synthetics, write atoms, relocate
emit      header + load commands
finalize  chains, then LC_UUID, then the code signature
```

Two steps differ from an ELF linker's for reasons specific to Mach-O. `__TEXT`
begins at file offset 0 and contains the load commands, so their size is an
*input* to address assignment and has to converge inside the fixpoint. And
`__LINKEDIT` must be last — dyld rejects an image with segment data after it —
so its size feeds back into nothing except the total file size, which is what
lets `unwind`, `fixups`, and `linkedit` run after layout and before `Freeze`.

The archive fixpoint matches `ld`, not traditional Unix `ld`: archives are
re-searched whenever anything new becomes undefined, so command-line order does
not decide what gets pulled in. It terminates because extraction is monotonic,
not because of any bound on iterations.

Resolution order is objects, then archives, then libraries. A definition in an
object or archive member wins over one in a dylib — otherwise a program could
never override a library function.

### `codesign` — signatures

Independent of the rest of the tree. The embedded signature is a `SuperBlob`
(`0xFADE0CC0`) indexing a `CodeDirectory` (`0xFADE0C02`), a requirements
vector, optional entitlements, and a CMS `SignedData`. All blob headers are
big-endian regardless of host or slice.

There are two paths, and they are not the same layout:

- `Size` + `Sign` in `codesign.go` produce the minimal linker-style ad-hoc
  signature — one blob, no special slots, `CS_ADHOC | CS_LINKER_SIGNED` — which
  is what `ld64` emits. `Size` is callable during address assignment so the
  slot can be reserved before the file exists.
- `SignFile` / `SignImage` in `sign.go` produce the full `codesign` layout with
  a requirements blob and optional entitlements, ad-hoc or with a real
  identity. It does a pre-pass with zero-filled hashes to learn the exact final
  size, patches the load commands, *then* hashes — because the hashes cover the
  command that describes the signature.

The final short page is hashed over its real bytes and never zero-padded, which
matches Apple's `codesign`, the Darwin linker, and the kernel's page
validation.

`SignFile` writes through a temporary file and `rename(2)`. That is not
tidiness: the kernel caches code signatures per vnode on Apple Silicon, and
overwriting in place can leave a stale cached signature.

Identities load from PEM (`LoadIdentityPEM`). PKCS#12 is out of scope to keep
the package pure-stdlib; convert with `openssl pkcs12` first.

---

## Quick start

### Read an object

```go
f, err := obj.Open("hello.o")
if err != nil {
    return err
}
defer f.Close()

fmt.Println(f.Target())   // arm64/macos/14.0/little/64

for _, s := range f.Sections {
    fmt.Printf("%s %6d bytes  align=%d  %v\n", s, s.Size, s.Align, s.Type())
}

syms, err := f.Symbols()
if err != nil {
    return err
}
for _, s := range syms {
    if s.Ext() && s.Undefined() {
        fmt.Println("undefined:", s.Name)
    }
}
```

### Write an object

```go
t, _ := macho.ParseTarget("arm64-apple-macosx14.0")

w := obj.NewWriter(out, obj.Options{
    Target: t,
    Flags:  macho.MH_SUBSECTIONS_VIA_SYMBOLS,
    Build:  t.Build(),
})

text := w.Section(obj.SectionHeader{
    Segment: macho.SEG_TEXT,
    Name:    macho.SECT_TEXT,
    Type:    macho.S_REGULAR,
    Attrs:   macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
    Align:   4, // BYTES, not log2
})
text.Write(code)

mainSym := w.Symbol(obj.SymbolDef{
    Name: "_main", Ext: true, Type: macho.N_SECT, Section: text,
})
puts := w.Symbol(obj.SymbolDef{Name: "_puts", Ext: true})

w.Reloc(text, obj.RelocSpec{
    Address: 0x10, Sym: puts,
    Type: uint8(macho.ARM64_RELOC_BRANCH26), PCRel: true, Length: macho.RelocLong,
})
w.LinkerOption("-framework", "Foundation")

err := w.Close()
```

### Paired relocations

Both halves go through one call so the adjacency invariant cannot be broken
from outside:

```go
w.RelocPair(text,
    obj.RelocSpec{Address: 0x20, Sym: mainSym, Type: uint8(macho.ARM64_RELOC_SUBTRACTOR), Length: macho.RelocQuad},
    obj.RelocSpec{Address: 0x20, Sym: puts,    Type: uint8(macho.ARM64_RELOC_UNSIGNED),   Length: macho.RelocQuad},
)
```

Submitting either half alone is `obj.ErrUnpairedReloc` at `Close`.

### Link an executable

```go
import (
    "github.com/vertex-language/macho"
    "github.com/vertex-language/macho/link"
    _ "github.com/vertex-language/macho/arm64" // registers the backend
)

t, err := macho.ParseTarget("arm64-apple-macosx14.0")
if err != nil {
    return err
}
l, err := link.New(t)
if err != nil {
    return err
}
l.SetEntry("_main")
if err := l.OpenFile("main.o"); err != nil {
    return err
}
if err := l.AddStub("libSystem.tbd", libSystemTBD); err != nil {
    return err
}

img, err := l.Link()
if err != nil {
    return err
}
b, err := img.Bytes()
if err != nil {
    return err
}
os.WriteFile("a.out", b, 0o755)
```

There is no static-versus-dynamic switch. Mach-O has no static link in the ELF
sense — everything resolves against `libSystem` — so a link with no dylib or
`.tbd` input fails with `link.ErrNoLibSystem` rather than producing something
`dyld` will reject.

The object writer's output is the linker's input directly, with no file
round-trip: `l.AddObject("generated.o", buf.Bytes())`.

### Universal files

```go
ff, err := fat.Open("libfoo.dylib")
if err != nil {
    return err
}
ext, err := ff.ExtentFor(t)          // graded selection, then a bounded view
f, err := obj.NewFile(ext)           // parsed in place, no copy

err = fat.Write(out, []fat.Member{
    {CPU: macho.CPU_TYPE_ARM64,  SubCPU: macho.CPU_SUBTYPE_ARM64_ALL,  Data: arm64Bytes},
    {CPU: macho.CPU_TYPE_X86_64, SubCPU: macho.CPU_SUBTYPE_X86_64_ALL, Data: amd64Bytes},
})
```

### Archives

```go
aw := ar.NewWriter(out, ar.Options{Deterministic: true})
aw.Add(ar.Input{Name: "hello.o", Data: helloObj, Symbols: syms})
err := aw.Close()

lib, err := ar.Open("libhello.a")
m, err := lib.Lookup("_main")        // walks even a sorted TOC; see read.go
```

### Stub libraries

```go
st, err := tbd.Parse(tbdBytes)
if err != nil {
    return err
}
fmt.Println(st.InstallName, st.CurrentVersion)
for _, s := range st.Exports(t) {    // filtered to one arch-platform target
    fmt.Println(s.Name, s.Kind)      // Global | Weak | ThreadLocal | ObjCClass | …
}
for _, lib := range st.ReexportedLibraries(t) {
    // follow these, or none of libc resolves
}
```

### Sign an existing binary

```go
id, err := codesign.LoadIdentityPEM("developer.pem", "developer.key")
if err != nil {
    return err
}
res, err := codesign.SignFile("a.out", codesign.Options{
    Identity:     id,
    Identifier:   "com.example.hello",
    Entitlements: entXML,
    Logger:       codesign.NewLogger(os.Stderr, codesign.VerbosityV2),
})
```

Leaving `Identity` nil is the ad-hoc path. On Apple Silicon it is not optional:
an arm64 macOS binary will not execute without at least an ad-hoc signature.

---

## Target and detection

```go
type Target struct {
    CPU      CPU
    SubCPU   SubCPU
    Platform Platform
    MinOS    Version
    SDK      Version
    Endian   Endian
}

func ParseTarget(triple string) (Target, error)
func (t Target) Width() Width
func (t Target) Valid() bool
func (t Target) String() string   // "arm64e/macos/14.0/little/64"
```

- The environment component decides the platform: `arm64-apple-ios17.0` is
  `PlatformIOS`, `-simulator` is `PlatformIOSSimulator`, `-macabi` is
  `PlatformMacCatalyst`. They are distinct platforms, not a flag on one.
- `arm64e` parses to `CPU_TYPE_ARM64` with `SubCPU = CPU_SUBTYPE_ARM64E`.
- `Width` is not a field. A `Target` claiming a 64-bit width for a 32-bit CPU
  cannot be constructed.
- `LC_VERSION_MIN_*` is read but never written: it cannot express Mac
  Catalyst, the simulators, DriverKit, or a tool version.

```go
macho.MagicSize   // 4  — bytes Is and IsFat need
macho.KindPrefix  // 16 — bytes KindOf needs

macho.Is(head)        // thin Mach-O magic, either byte order and width
macho.IsFat(head)     // 0xCAFEBABE / 0xCAFEBABF, with Java class disambiguation
macho.KindOf(head)    // KindObject | KindExecute | KindDylib | …
macho.TargetOf(head)  // CPU and SubCPU, for picking a fat slice
```

`KindOf` verifies the magic before trusting the byte order it implies, and
reports `ErrFatFile` rather than a garbage kind when handed a fat header.

---

## Configuration without linker scripts

`ld64` never had `SECTIONS` scripts and neither does this. Everything such a
script would express is a field on `link.Options` or a setter on `Linker`:

```go
l.SetOrderFile(symbols)                                  // -order_file
l.AddSectionData("__TEXT", "__info_plist", plistBytes)   // -sectcreate
l.SetSegmentAddress("__TEXT", 0x1_0000_0000)             // -segaddr
l.SetSegmentProt("__DATA_CONST", maxProt, initProt)      // -segprot
l.SetPageZeroSize(0x1_0000_0000)                         // -pagezero_size
l.SetExportedSymbols(list)                               // -exported_symbols_list
l.KeepPrivateExterns(true)                               // -keep_private_externs
l.SetInstallName("/usr/lib/libfoo.dylib")                // -install_name
l.SetDylibVersions(current, compat)                      // -current_version …
l.AddRPath("@executable_path/../Frameworks")             // -rpath
l.SetBundleLoader(execPath)                              // -bundle_loader
l.ForceLoad("libfoo.a")                                  // -force_load
l.LoadAllObjC(true)                                      // -ObjC
l.DeadStrip(true)                                        // -dead_strip
l.SetUndefinedTreatment(link.UndefinedDynamicLookup)     // -undefined dynamic_lookup
l.SetNamespace(link.NamespaceTwoLevel)                   // -twolevel_namespace
```

`SetSegmentAddress` genuinely pins the segment, unlike its ELF counterpart —
Mach-O segments carry an explicit `vmaddr`, so there is nothing to infer.

`SegmentAddress` and `SegmentProt` are **read by nothing**: `assign.go` places
segments from the page size and the section contents and never consults either
map. That is a gap, not a design.

Two options interact in a way worth stating. `NamespaceFlat` disables library
ordinal recording, so `UndefinedError` can no longer name the library a symbol
was expected from. That degradation matches `ld64` and is intentional, but it
is a real loss of diagnostic quality.

And one default that surprises people: `CommonsIgnoreDylibs` means a tentative
definition in an object silently beats an exported definition of the same name
in a linked library. That matches `ld64`. `CommonsError` is what a build that
cares should use.

---

## Known gaps

Called out here rather than left for a failing run to explain. The build errors
are in [Status](#does-not-build); these are things that compile and do not work.

**`link` and `codesign` do not agree on an API.** `link/emit.go` calls
`codesign.SignImage(img *image.Image, opts)`; the real signature is
`SignImage(raw []byte, opts Options) ([]byte, error)`. Reconciling them means
either a `SignBuffer` that patches an `*image.Image` in place, or `link`
handing over bytes and taking bytes back — which conflicts with the signature
being written into a slot `image` reserved and hashed in place. This is the
single largest unresolved seam in the tree.

**`link/assign.go`'s `codeSignatureSize` duplicates `codesign.Size`.** It is a
generous local estimate written before the `codesign` API was in view. It
should call `codesign.Size(fileSize, identifier)`, which is exactly the
function that exists for this purpose. If the local estimate is ever *under*,
`Freeze`'s "nothing may follow the signature" check passes and the signature is
truncated.

**`assign.commands` and `emit` are two descriptions of one load-command list.**
The fixpoint needs the block's size before the block can be built. Only the
totals are compared, so swapping one 16-byte command for another passes the
check and produces a wrong file. The fix is a `[]command` plan built once.

**`merge.sectionOf` reads `l.atomSection`, which nothing populates.** Every
atom therefore falls through to the "linker-generated" default and lands in
`__TEXT,__text`. `splitInput` knows each atom's originating `obj.Section` and
should record the key there — one line at the end of that function.

**`merge.redirect` is O(atoms × relocs) per fold.** For a program with a
million literals that is quadratic and dominates link time. The forwarding is
already recorded in `l.folded`; it wants to be applied in one pass after all
folding is done.

**Common symbols get no storage.** `resolve.resolveCommons` promotes a
tentative definition to `ClassDefined` and leaves `split` to create the
`__DATA,__common` zerofill atom, which `split` does not do. `assign.bindSymbols`
reports it by name rather than binding zero.

**Alt-entry symbols bind to the wrong address.** `image.Sym` has no
offset-within-atom, so a `.alt_entry` symbol gets its containing atom's start
address. Every other symbol is correct. The fix is one field on `Sym` threaded
through `split.bySymbol`.

**`unwind.lastLength` is wrong.** It returns the length of the last entry in
insertion order, not the last by address. The sentinel index entry's function
offset is the only thing bounding the final function, so a lookup just past the
last function returns that function's unwind info instead of nothing.

**`__unwind_info` uses regular second-level pages only.** Compressed pages hold
1021 entries to a regular page's 511, but need an encoding palette and a 24-bit
function delta that both depend on final addresses — which are not known when
the section must be sized. Roughly twice the bytes, in a section that is a low
single-digit percentage of a binary. Moving `unwind` inside the layout fixpoint
is the prerequisite.

**An `__eh_frame` FDE's reference to its function is not canonicalized.** It is
pc-relative from the FDE's own address, so dead-stripping or reordering
anything before it changes the value the relocation should produce. `ld64` and
`lld` place a symbol at the FDE's start at split time. An `__eh_frame` that
survives dead-stripping unchanged is correct; one that does not is not.

**Lazy stubs are unreachable.** `arm64` and `x86_64` both implement the full
lazy sequence, but `link/order.go` returns `ErrUnimplemented` at the point it
would need each entry's offset into the lazy bind opcode stream, which
`fixups.go` does not produce. Non-lazy is the default and the one to prefer
anyway: under chained fixups `dyld` binds the image at load, so lazy binding
costs three sections and a writable code path for nothing.

**No classic `LC_DYLD_INFO_ONLY` path.** Chained fixups only, which means no
deployment target older than the chained format.

**arm64e and arm64_32 do not exist as packages.** `arm64.Config` carries a
`PtrAuth` hook and a `WordSize` so they can be built without duplicating the
instruction encoders, and `backend.PtrAuth` describes a signing schema — but
nothing encodes an authenticated chain entry, and `link/fixups.go` reports
`DYLD_CHAINED_PTR_32` and `..._ARM64E_USERLAND24` as unimplemented rather than
approximating them.

**Chained-fixup addends are capped at 8 bits.** The 64-bit bind entry carries
`addend:8`. `DYLD_CHAINED_IMPORT_ADDEND` and `_ADDEND64` exist for larger ones
and change the import table's element size; a larger addend is an error naming
the symbol.

**Linker optimization hints are collected and never applied.** `obj/loh.go`
reads them, `link/relax.go` resolves them to atoms and drops any that span
atom boundaries, and no backend implements `backend.Relaxer`, so `adrp`+`add` →
`adr`/`nop` does not happen. The instruction checks are written down in
`arm64/insn.go` and `x86_64/insn.go` so they are not reinvented.

**GOT loads are never relaxed.** When a `GOT_LOAD` turns out to reference a
symbol defined in this image, the `LDR` can become an `ADD` and the slot can
disappear — but `Scan` would have to decide, before any address exists, which
slots survive, and a slot wrongly elided is an image that faults. Every
`GOT_LOAD` gets a slot: eight bytes per symbol.

**Thunks are one island.** All veneers land in `__TEXT,__thunks`. Correct while
`__TEXT` is under 128 MiB, and above that a branch cannot reach its own thunk —
reported as a `backend.RangeError` rather than encoded silently. Distributed
islands are the next step.

**`LC_UUID` is SHA-256 truncated to sixteen bytes.** `ld64` uses MD5. `dyld`
only wants uniqueness, so this is correct — but it means the UUID is not a way
to check this linker against that one, and a golden diff will differ in exactly
that field.

**Reading a real dylib is unimplemented.** `link.AddDylib` returns
`ErrUnimplemented`; there is no `link/read.go`, and `internal/trie` has a
builder and no walker. Everything a link actually needs from a system library
is in its `.tbd`, so `AddStub` is the path that works.

**Objective-C is untouched.** No `__objc_imageinfo` merging, no category
merging, no ObjC stub synthesis. `Options.LoadAllObjC` is stored and never
read — which matters more than it sounds: a category has no symbol anything
references, so ordinary archive semantics drop it and its methods silently do
not exist at runtime.

**ICF is not implemented**, and `ld -r` partial output is not implemented — it
needs relocation regeneration, which nothing does.

**`.tbd` v5 is unimplemented**, detected and rejected rather than half-parsed.

**DER entitlements are wired but never emitted.** `derEntitlements` and slot 7
exist; `signSlice` only ever populates the XML slot. macOS 12+ expects both
when entitlements are present.

**No golden-file or fuzz tests exist.** The stated policy — diff `obj` output
against `llvm-readobj --macho` and `otool -lv`, images against `otool -l` and
`dyld_info`, signatures against `codesign -dvvv`; fuzz `binio.Cursor`, `obj`,
`fat`, `ar`, and `tbd`'s YAML reader — is a commitment, not a description.
`fat`, the load-command walk, and the TBD parser are the highest-value fuzz
targets, since all three consume attacker-controlled offsets or shapes.

---

## Errors

| Error | Cause |
| --- | --- |
| `macho.ErrNotMachO` | Missing Mach-O magic |
| `macho.ErrShortHeader` | Buffer too short for the detection function called |
| `macho.ErrFatFile` | A universal file reached a thin reader |
| `macho.ErrThinFile` | A thin file reached `fat.NewFile` |
| `macho.ErrFatOverlap` | Slices overlap each other or the fat header |
| `macho.ErrNoMatchingSlice` | No slice matches the requested target |
| `macho.ErrInvalidTarget` | Triple or `Target` rejected by `Valid()` |
| `macho.ErrUnsupportedCPU` | `cputype` not in the seeded table |
| `binio.ErrTruncated` | A read ran past the end; `*BoundsError` unwraps to it |
| `binio.CountError` | A declared count cannot fit the remaining bytes |
| `binio.ErrOverflow` | A LEB128 value doesn't fit 64 bits |
| `binio.ErrNameTooLong` | A string doesn't fit a fixed-width field |
| `format.ErrWidth` | Decode/Encode called with an invalid `Width` |
| `strtab.ErrNulInString` | A string containing a NUL was added |
| `obj.ErrNotObject` | A linked image reached the object reader |
| `obj.ErrBadLoadCommand` | Invalid, unaligned, or non-advancing `cmdsize` |
| `obj.ErrBadSection` | Unshiftable alignment, or a section array that doesn't fit |
| `obj.ErrNoSymbolTable` | A lookup needed a symbol table the file lacks |
| `obj.ErrTooManySections` | More than 255 sections — the limit of `n_sect` |
| `obj.ErrFileTooLarge` | A file offset exceeded 4 GB |
| `obj.ErrBuildVersionRequired` | `Options.Build` left at its zero value |
| `obj.ErrUnpairedReloc` | A `SUBTRACTOR` or `ADDEND` without its partner |
| `obj.ErrBadRelocation` | Unencodable relocation, or one from another writer |
| `obj.ErrBadSymbol` | An internally inconsistent symbol definition |
| `fat.ErrNoSlices` | Zero slices declared, or none supplied to the writer |
| `fat.ErrDuplicateArch` | Two slices with the same `(cputype, cpusubtype)` |
| `fat.ErrBadAlign` | Alignment beyond `MaxAlign`, or an offset that violates it |
| `fat.ErrSliceBounds` | A slice extends past the end of the file |
| `ar.ErrNotArchive` | Missing `!<arch>` magic |
| `ar.ErrBadHeader` | Malformed member header, or one that doesn't advance |
| `ar.ErrSysVArchive` | SysV/GNU-variant archive, deliberately unsupported |
| `ar.ErrNoTOC` | No `__.SYMDEF` member; run `ranlib` |
| `ar.ErrBadTOC` | A table of contents inconsistent with itself |
| `tbd.ErrUnsupportedTBDVersion` | v5 (JSON), or an unrecognized document tag |
| `tbd.ErrNoMatchingTarget` | No export list for the requested arch-platform pair |
| `tbd.ErrMalformed` | A required key missing or unreadable |
| `image.ErrPhase` | An operation attempted in the wrong phase |
| `image.ErrNoSize` | An address or size read before assignment |
| `image.ErrNotFrozen` | The output buffer touched before `Freeze` |
| `image.ErrOutOfBounds` | A write outside the output buffer |
| `image.ErrLayout` | Overlap, misalignment, or a zerofill section not last |
| `backend.ErrNoBackend` | No backend for the target's CPU/SubCPU |
| `backend.ErrUnsupportedReloc` | An `r_type` this backend doesn't implement |
| `*backend.RangeError` | A value didn't fit the field being written |
| `link.ErrNoInputs` | Nothing was added |
| `link.ErrNoLibSystem` | No dylib or `.tbd` input; the result would not load |
| `link.ErrNoEntry` | Executable output with no resolvable entry point |
| `link.ErrLayoutDivergence` | The thunk/relaxation loop didn't converge |
| `link.ErrCPUMismatch` | Input architecture disagrees with the target |
| `link.ErrPlatformMismatch` | Input platform or `minos` incompatible |
| `link.ErrUnimplemented` | A path this tree does not have yet |
| `*link.UndefinedError` | Unresolved name, with referencing inputs and library |
| `*link.DuplicateError` | Multiple strong definitions, naming both sides |
| `*link.OrdinalError` | Two-level namespace: symbol found, wrong library |
| `*link.TooManyDylibsError` | More than 253 libraries |
| `*link.OverflowError` | A backend range failure, wrapped with its input file |

`codesign` has no sentinel errors; it returns formatted errors throughout.

---

## Roadmap

Ordered by what unblocks the most.

1. **Make it build.** The five errors above, plus the undeclared `link` fields
   and the two `image` phase relaxations. Everything else is downstream of a
   tree that compiles.
2. **Reconcile `link` and `codesign`.** One signing API, one size function.
   This is the last structural decision the tree has not made.
3. **Golden-file tests**, starting with `obj`: diff the writer's output against
   `llvm-readobj --macho` and `otool -lv` for a handful of real objects. The
   linker is downstream of every assumption that layer makes, so testing it
   first is testing the wrong thing.
4. **Fuzz `binio.Cursor`, the load-command walk, `fat`, `ar`, and `tbd`.**
5. **Common-symbol storage and alt-entry offsets** — the two places a symbol
   currently gets a wrong address rather than an error.
6. **Link a static-content executable end to end** and run it. That is the
   first moment any of this is known to work.
7. **`__unwind_info` compressed pages**, which means moving `unwind` inside the
   layout fixpoint.
8. **`link/read.go` and a trie walker**, so a real dylib can be a link input.
9. **`arm64e` with `Signer`, then `arm64_32`** — including the authenticated
   and 32-bit chained pointer formats.
10. **Linker optimization hints (`Relaxer`) and ICF**, both pure optimizations
    that need a correct linker first.
11. **Objective-C** — `__objc_imageinfo` merging, category merging, `-ObjC`.
12. **`.tbd` v5**, the classic `LC_DYLD_INFO_ONLY` fallback, and `ld -r`.