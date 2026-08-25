package codesign

// Magic numbers and slot/flag constants from XNU osfmk/kern/cs_blobs.h.
// All multi-byte fields in the on-disk code-signing structures are big-endian.

const (
	csmagicRequirement         uint32 = 0xfade0c00 // single Requirement blob
	csmagicRequirements        uint32 = 0xfade0c01 // Requirements vector
	csmagicCodeDirectory       uint32 = 0xfade0c02 // CodeDirectory blob
	csmagicEmbeddedSignature   uint32 = 0xfade0cc0 // embedded signature (top-level)
	csmagicDetachedSignature   uint32 = 0xfade0cc1 // multi-arch detached collection
	csmagicBlobWrapper         uint32 = 0xfade0b01 // CMS / PKCS#7 signature wrapper
	csmagicEmbeddedEntitlement uint32 = 0xfade7171 // XML entitlements plist
	csmagicDEREntitlement      uint32 = 0xfade7172 // DER-encoded entitlements
)

// CodeDirectory version milestones — each adds fields at the end of the struct.
const (
	csSupportsScatter     = 0x20100
	csSupportsTeamID      = 0x20200
	csSupportsCodeLimit64 = 0x20300
	csSupportsExecSeg     = 0x20400 // execSegBase/Limit/Flags — required on Apple Silicon
	csSupportsRuntime     = 0x20500 // runtime field present
	csSupportsLinkage     = 0x20600
)

// SuperBlob index slot numbers (the "type" in each BlobIndex entry).
const (
	csslotCodeDirectory          = 0
	csslotInfoSlot               = 1 // special slot -1
	csslotRequirements           = 2 // special slot -2
	csslotResourceDir            = 3 // special slot -3
	csslotApplication            = 4 // special slot -4
	csslotEntitlements           = 5 // special slot -5
	csslotRepSpecific            = 6 // special slot -6
	csslotDEREntitlements        = 7 // special slot -7
	csslotSignature       uint32 = 0x10000 // CMS signature (not a special slot)
)

// Hash algorithm identifiers stored in CodeDirectory.hashType.
const (
	csHashTypeSHA1            = 1
	csHashTypeSHA256          = 2
	csHashTypeSHA256Truncated = 3
	csHashTypeSHA384          = 4
)

// CodeDirectory.flags (CS_*).
const (
	csAdhoc        uint32 = 0x00000002 // ad-hoc signed; no identity
	csRuntime      uint32 = 0x00010000 // hardened runtime
	csLinkerSigned uint32 = 0x00020000 // automatically signed by the linker
)

// Executable-segment flags (CodeDirectory.execSegFlags).
const (
	csExecSegMainBinary    uint64 = 0x01 // this slice is the main executable
	csExecSegAllowUnsigned uint64 = 0x10 // allow unsigned pages (debug only)
	csExecSegJIT           uint64 = 0x40 // JIT enabled
)

// cdhash truncation length used for the "One True CDHash".
const cdHashLen = 20

// Page size used for code hashing: 4 KiB (log2 = 12).
const (
	pageSizeBits = 12
	pageSize     = 1 << pageSizeBits
)