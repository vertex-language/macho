package codesign

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// -----------------------------------------------------------------------
// On-disk struct sizes (all fields big-endian).
//
//   SuperBlob header  : magic(4) + length(4) + count(4)          = 12
//   BlobIndex entry   : type(4)  + offset(4)                     =  8
//   CodeDirectory     : fixed header for version 0x20400          = 88
// -----------------------------------------------------------------------
const (
	superBlobSize     = 12
	blobIndexSize     = 8
	codeDirectorySize = 88
)

// Size returns the exact number of bytes that must be reserved for the
// ad-hoc code signature of a binary whose signed region is codeSize bytes
// long and whose CodeDirectory identifier string is id.
//
// Call this during the address-assignment phase of linking so that the
// __LINKEDIT segment and LC_CODE_SIGNATURE load command can be sized before
// the binary is emitted.
func Size(codeSize int64, id string) int64 {
	nhashes := (codeSize + pageSize - 1) / pageSize
	// CodeDirectory layout after the fixed header:
	//   [identOffset]  identifier C-string (len(id)+1 bytes incl. NUL)
	//   [hashOffset]   nhashes × sha256.Size
	idOff := int64(codeDirectorySize)
	hashOff := idOff + int64(len(id)+1)
	cdSize := hashOff + nhashes*sha256.Size

	// One SuperBlob header + one BlobIndex entry + the CodeDirectory blob.
	return int64(superBlobSize+blobIndexSize) + cdSize
}

// Sign computes and writes an ad-hoc code signature into out.
//
// Parameters:
//   - out       destination buffer; must be at least Size(codeSize, id) bytes.
//   - data      the complete binary content up to (but not including) the
//               signature region, i.e. exactly codeSize bytes.
//   - id        signing identifier embedded in the CodeDirectory (typically
//               the binary's filename or bundle identifier).
//   - codeSize  byte length of the region being signed.
//   - textOff   file offset of the __TEXT segment (used for execSegBase).
//   - textSize  byte size of the __TEXT segment (used for execSegLimit).
//   - isMain    true for MH_EXECUTE / PIE output; sets CS_EXECSEG_MAIN_BINARY.
//
// Sign does not return an error; a short read from data will panic — the
// caller is expected to pass a complete, correctly-sized buffer.
func Sign(out []byte, data io.Reader, id string, codeSize, textOff, textSize int64, isMain bool) {
	nhashes := (codeSize + pageSize - 1) / pageSize
	idOff := int64(codeDirectorySize)
	hashOff := idOff + int64(len(id)+1)
	sz := Size(codeSize, id)
	cdSize := sz - int64(superBlobSize+blobIndexSize)

	// ── CodeDirectory flags ──────────────────────────────────────────────
	// CS_ADHOC only.  CS_LINKER_SIGNED is only valid for the minimal
	// linker-emitted signature (nSpecialSlots=0, no Requirements blob).
	// This function produces that same minimal layout, so CS_LINKER_SIGNED
	// is also set here to match exactly what the Darwin linker emits.
	// (sign.go / signSlice does NOT set CS_LINKER_SIGNED because it
	// produces the full codesign layout with a Requirements blob.)
	flags := csAdhoc | csLinkerSigned

	var execSegFlags uint64
	if isMain {
		execSegFlags = csExecSegMainBinary
	}

	// ── Write SuperBlob header ───────────────────────────────────────────
	b := out
	b = putU32be(b, csmagicEmbeddedSignature)
	b = putU32be(b, uint32(sz))
	b = putU32be(b, 1) // one blob (the CodeDirectory)

	// ── Write BlobIndex[0] ───────────────────────────────────────────────
	b = putU32be(b, csslotCodeDirectory)
	b = putU32be(b, uint32(superBlobSize+blobIndexSize)) // offset to CD blob

	// ── Write CodeDirectory fixed header (version 0x20400, 88 bytes) ────
	b = putU32be(b, csmagicCodeDirectory)
	b = putU32be(b, uint32(cdSize))
	b = putU32be(b, csSupportsExecSeg)    // version
	b = putU32be(b, flags)
	b = putU32be(b, uint32(hashOff))      // hashOffset  (from CD start)
	b = putU32be(b, uint32(idOff))        // identOffset (from CD start)
	b = putU32be(b, 0)                    // nSpecialSlots — none for linker ad-hoc
	b = putU32be(b, uint32(nhashes))      // nCodeSlots
	b = putU32be(b, uint32(codeSize))     // codeLimit
	b = putU8(b, sha256.Size)             // hashSize
	b = putU8(b, csHashTypeSHA256)        // hashType
	b = putU8(b, 0)                       // platform (0 = not a platform binary)
	b = putU8(b, pageSizeBits)            // pageSize = log2(4096) = 12
	b = putU32be(b, 0)                    // spare2
	// v0x20100
	b = putU32be(b, 0)                    // scatterOffset (unused)
	// v0x20200
	b = putU32be(b, 0)                    // teamOffset (no team ID for ad-hoc)
	// v0x20300
	b = putU32be(b, 0)                    // spare3
	b = putU64be(b, 0)                    // codeLimit64 (0 = use 32-bit codeLimit)
	// v0x20400
	b = putU64be(b, uint64(textOff))      // execSegBase
	b = putU64be(b, uint64(textSize))     // execSegLimit
	b = putU64be(b, execSegFlags)         // execSegFlags

	// ── Write identifier C-string ────────────────────────────────────────
	b = puts(b, []byte(id))
	b = putU8(b, 0) // NUL terminator

	// ── Hash each 4 KiB page and write into code slots ───────────────────
	// Each page is hashed over exactly its real bytes — for full pages that
	// is 4096 bytes; for the final short page it is (codeSize % pageSize)
	// bytes only.  Zero-padding the last page would produce a different hash
	// from what the kernel computes when it validates the mapped pages, and
	// from what Apple's codesign and the Go toolchain both emit.
	var pageBuf [pageSize]byte
	remaining := codeSize
	h := sha256.New()

	for remaining > 0 {
		n := int64(pageSize)
		if n > remaining {
			n = remaining
		}
		if _, err := io.ReadFull(data, pageBuf[:n]); err != nil {
			panic("codesign.Sign: short read from data: " + err.Error())
		}
		h.Reset()
		h.Write(pageBuf[:n]) // hash only actual bytes; never zero-pad
		digest := h.Sum(nil)
		b = puts(b, digest)
		remaining -= n
	}
}

// -----------------------------------------------------------------------
// Big-endian serialisation helpers.
// Each helper writes into the head of b and returns the remaining slice.
// -----------------------------------------------------------------------

func putU32be(b []byte, v uint32) []byte {
	binary.BigEndian.PutUint32(b, v)
	return b[4:]
}

func putU64be(b []byte, v uint64) []byte {
	binary.BigEndian.PutUint64(b, v)
	return b[8:]
}

func putU8(b []byte, v uint8) []byte {
	b[0] = v
	return b[1:]
}

func puts(b, s []byte) []byte {
	n := copy(b, s)
	return b[n:]
}

// -----------------------------------------------------------------------
// LoadCmdData is the on-disk layout of an LC_CODE_SIGNATURE load command.
// Emit this into the Mach-O load command region during binary construction,
// then patch Dataoff and Datasize once the final file layout is known.
// -----------------------------------------------------------------------

// CodeSigCmd is the wire layout of the LC_CODE_SIGNATURE load command.
// All fields are little-endian (matching the rest of the Mach-O header).
type CodeSigCmd struct {
	Cmd      uint32 // lcCodeSignature = 0x1d
	CmdSize  uint32 // always 16
	DataOff  uint32 // file offset of signature data in __LINKEDIT
	DataSize uint32 // byte length == Size(codeSize, id)
}

// MarshalLE serialises cmd into buf (must be ≥ 16 bytes) in little-endian
// byte order, matching the Mach-O load-command convention.
func (cmd CodeSigCmd) MarshalLE(buf []byte) {
	binary.LittleEndian.PutUint32(buf[0:], cmd.Cmd)
	binary.LittleEndian.PutUint32(buf[4:], cmd.CmdSize)
	binary.LittleEndian.PutUint32(buf[8:], cmd.DataOff)
	binary.LittleEndian.PutUint32(buf[12:], cmd.DataSize)
}

// NewCodeSigCmd returns a CodeSigCmd ready to embed in a Mach-O load command
// region.  dataOff is the file offset immediately following the last byte of
// the binary's non-signature content; dataSize should be the result of
// Size(codeSize, id).
func NewCodeSigCmd(dataOff, dataSize uint32) CodeSigCmd {
	return CodeSigCmd{
		Cmd:      lcCodeSignature,
		CmdSize:  16,
		DataOff:  dataOff,
		DataSize: dataSize,
	}
}