package macho

// CPU is a Mach-O cputype.
//
// The architecture bits in the high byte are part of the value, not a separate
// field: CPU_TYPE_X86_64 is literally CPU_TYPE_X86 | CPU_ARCH_ABI64. This is
// why Width is derived rather than stored.
type CPU uint32

// Architecture capability bits within a cputype.
const (
	CPU_ARCH_MASK CPU = 0xff000000

	// CPU_ARCH_ABI64 marks a 64-bit ABI with 64-bit pointers (LP64).
	CPU_ARCH_ABI64 CPU = 0x01000000

	// CPU_ARCH_ABI64_32 marks 64-bit hardware running a 32-bit-pointer ABI
	// (ILP32). This is a distinct bit from CPU_ARCH_ABI64, not a modifier of
	// it — arm64_32 has ABI64_32 set and ABI64 clear, and therefore has
	// Width32. Getting this backwards produces a header with the wrong magic.
	CPU_ARCH_ABI64_32 CPU = 0x02000000
)

const (
	CPU_TYPE_ANY CPU = 0xffffffff // (cpu_type_t)-1

	CPU_TYPE_X86    CPU = 7
	CPU_TYPE_I386   CPU = CPU_TYPE_X86
	CPU_TYPE_X86_64 CPU = CPU_TYPE_X86 | CPU_ARCH_ABI64

	CPU_TYPE_ARM      CPU = 12
	CPU_TYPE_ARM64    CPU = CPU_TYPE_ARM | CPU_ARCH_ABI64
	CPU_TYPE_ARM64_32 CPU = CPU_TYPE_ARM | CPU_ARCH_ABI64_32

	CPU_TYPE_POWERPC   CPU = 18
	CPU_TYPE_POWERPC64 CPU = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
)

// Width derives the pointer width from the CPU_ARCH_ABI64 bit. It is the only
// definition of width in this package; there is no Bits field and no wide bool.
func (c CPU) Width() Width {
	if c&CPU_ARCH_ABI64 != 0 {
		return Width64
	}
	return Width32
}

// Wide reports whether c uses 64-bit pointers.
func (c CPU) Wide() bool { return c.Width().Wide() }

// Endian returns the byte order for c. Every CPU in the seeded table is
// little-endian; big-endian Mach-O (ppc, ppc64) is readable but is not a
// target this tree emits.
func (c CPU) Endian() Endian {
	switch c {
	case CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64:
		return BigEndian
	}
	return LittleEndian
}

// Supported reports whether c is a CPU this tree can act as a target for.
func (c CPU) Supported() bool {
	switch c {
	case CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_X86_64:
		return true
	}
	return false
}

func (c CPU) String() string {
	switch c {
	case CPU_TYPE_X86:
		return "i386"
	case CPU_TYPE_X86_64:
		return "x86_64"
	case CPU_TYPE_ARM:
		return "arm"
	case CPU_TYPE_ARM64:
		return "arm64"
	case CPU_TYPE_ARM64_32:
		return "arm64_32"
	case CPU_TYPE_POWERPC:
		return "ppc"
	case CPU_TYPE_POWERPC64:
		return "ppc64"
	case CPU_TYPE_ANY:
		return "any"
	}
	return "cputype(?)"
}

// SubCPU is a Mach-O cpusubtype.
//
// SubCPU is a first-class axis, not a detail of CPU. arm64e is a cpusubtype of
// CPU_TYPE_ARM64, not its own cputype, and it carries ptrauth ABI information
// in the capability byte. Every comparison must mask with Base() first; Caps()
// preserves the capability bits so they can round-trip through a fat header
// unchanged.
type SubCPU uint32

const (
	// CPU_SUBTYPE_MASK covers the capability byte, bits 31:24.
	CPU_SUBTYPE_MASK SubCPU = 0xff000000

	// CPU_SUBTYPE_LIB64 appears on slices that want 64-bit libraries.
	CPU_SUBTYPE_LIB64 SubCPU = 0x80000000

	// CPU_SUBTYPE_MULTIPLE is (cpu_subtype_t)-1.
	CPU_SUBTYPE_MULTIPLE SubCPU = 0xffffffff
)

// x86 subtypes. CPU_SUBTYPE_X86_64_ALL is 3, sharing the value of
// CPU_SUBTYPE_I386_ALL; it is not 0, which is a common assumption and wrong.
const (
	CPU_SUBTYPE_I386_ALL   SubCPU = 3
	CPU_SUBTYPE_X86_64_ALL SubCPU = CPU_SUBTYPE_I386_ALL
	CPU_SUBTYPE_X86_64_H   SubCPU = 8 // Haswell and later
)

// arm64 subtypes.
const (
	CPU_SUBTYPE_ARM64_ALL SubCPU = 0
	CPU_SUBTYPE_ARM64_V8  SubCPU = 1
	CPU_SUBTYPE_ARM64E    SubCPU = 2
)

// arm64_32 subtypes.
const (
	CPU_SUBTYPE_ARM64_32_ALL SubCPU = 0
	CPU_SUBTYPE_ARM64_32_V8  SubCPU = 1
)

// arm64e encodes its ptrauth ABI in the capability byte. These bits live
// inside CPU_SUBTYPE_MASK, so Base() strips them and Caps() keeps them.
//
// A binary with CPU_SUBTYPE_ARM64E and ptrauth version 0 is the preview ABI;
// the macOS kernel refuses to execute one unless it is a platform binary. Any
// arm64e output this tree produces must therefore carry a versioned ABI.
const (
	CPU_SUBTYPE_ARM64E_VERSIONED_PTRAUTH_ABI_MASK SubCPU = 0x80000000 // bit 31
	CPU_SUBTYPE_ARM64E_KERNEL_PTRAUTH_ABI_MASK    SubCPU = 0x40000000 // bit 30
	CPU_SUBTYPE_ARM64E_PTRAUTH_MASK               SubCPU = 0x0f000000 // bits 27:24
)

// Base returns s with the capability byte cleared. Compare with this, never
// with the raw value.
func (s SubCPU) Base() SubCPU { return s &^ CPU_SUBTYPE_MASK }

// Caps returns only the capability byte of s.
func (s SubCPU) Caps() SubCPU { return s & CPU_SUBTYPE_MASK }

// PtrAuthVersion returns the 4-bit arm64e ptrauth ABI version and whether the
// binary is marked as carrying a versioned ABI at all. It is meaningless
// unless s.Base() == CPU_SUBTYPE_ARM64E.
func (s SubCPU) PtrAuthVersion() (version uint8, versioned bool) {
	return uint8((s & CPU_SUBTYPE_ARM64E_PTRAUTH_MASK) >> 24),
		s&CPU_SUBTYPE_ARM64E_VERSIONED_PTRAUTH_ABI_MASK != 0
}

// PtrAuthKernelABI reports whether s marks the arm64e kernel ptrauth ABI.
func (s SubCPU) PtrAuthKernelABI() bool {
	return s&CPU_SUBTYPE_ARM64E_KERNEL_PTRAUTH_ABI_MASK != 0
}

// ARM64EWithPtrAuth builds an arm64e cpusubtype carrying a versioned ptrauth
// ABI. version must fit in 4 bits.
func ARM64EWithPtrAuth(version uint8, kernel bool) SubCPU {
	s := CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_VERSIONED_PTRAUTH_ABI_MASK
	if kernel {
		s |= CPU_SUBTYPE_ARM64E_KERNEL_PTRAUTH_ABI_MASK
	}
	return s | (SubCPU(version&0x0f) << 24)
}

// ArchName returns the toolchain arch name for a (CPU, SubCPU) pair — the
// string clang and lipo use, such as "arm64e". It masks with Base() first.
func ArchName(c CPU, s SubCPU) string {
	switch c {
	case CPU_TYPE_ARM64:
		if s.Base() == CPU_SUBTYPE_ARM64E {
			return "arm64e"
		}
		return "arm64"
	case CPU_TYPE_ARM64_32:
		return "arm64_32"
	case CPU_TYPE_X86_64:
		if s.Base() == CPU_SUBTYPE_X86_64_H {
			return "x86_64h"
		}
		return "x86_64"
	}
	return c.String()
}

// ParseArch maps a toolchain arch name to a (CPU, SubCPU) pair.
func ParseArch(name string) (CPU, SubCPU, bool) {
	switch name {
	case "arm64":
		return CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, true
	case "arm64e":
		return CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, true
	case "arm64_32":
		return CPU_TYPE_ARM64_32, CPU_SUBTYPE_ARM64_32_V8, true
	case "x86_64":
		return CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, true
	case "x86_64h":
		return CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H, true
	}
	return 0, 0, false
}