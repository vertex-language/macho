package codesign

import (
	"crypto"
	"encoding/binary"
	"sort"
)

// cdParams describes everything needed to emit one CodeDirectory.
type cdParams struct {
	identifier string
	teamID     string
	flags      uint32
	hashType   uint8
	pageBits   uint8
	codeLimit  int64
	execBase   int64
	execLimit  int64
	execFlags  uint64
	platform   uint8

	codeHashes    [][]byte          // one per page, in order
	specialHashes map[int][]byte    // slot index (1..7) -> hash; 0 entries left zeroed
}

func hashFor(t uint8) crypto.Hash {
	switch t {
	case csHashTypeSHA1:
		return crypto.SHA1
	case csHashTypeSHA384:
		return crypto.SHA384
	default:
		return crypto.SHA256
	}
}

// buildCodeDirectory serialises a version-0x20400 CodeDirectory. Special slots
// occupy negative indices and are stored immediately before code slot 0, in
// order -nSpecial … -1.
func buildCodeDirectory(p cdParams) []byte {
	h := hashFor(p.hashType)
	hashSize := h.Size()

	nSpecial := 0
	for slot := range p.specialHashes {
		if slot > nSpecial {
			nSpecial = slot
		}
	}
	nCode := len(p.codeHashes)

	const fixed = 88 // header bytes through execSegFlags (version 0x20400)
	idOff := fixed
	teamOff := idOff + len(p.identifier) + 1
	teamLen := 0
	if p.teamID != "" {
		teamLen = len(p.teamID) + 1
	}
	hashOff := teamOff + teamLen + nSpecial*hashSize // hashes for slot 0 start here
	total := hashOff + nCode*hashSize

	b := make([]byte, total)
	be := binary.BigEndian
	be.PutUint32(b[0:], csmagicCodeDirectory)
	be.PutUint32(b[4:], uint32(total))
	be.PutUint32(b[8:], csSupportsExecSeg) // version
	be.PutUint32(b[12:], p.flags)
	be.PutUint32(b[16:], uint32(hashOff))
	be.PutUint32(b[20:], uint32(idOff))
	be.PutUint32(b[24:], uint32(nSpecial))
	be.PutUint32(b[28:], uint32(nCode))
	be.PutUint32(b[32:], uint32(p.codeLimit))
	b[36] = byte(hashSize)
	b[37] = p.hashType
	b[38] = p.platform
	b[39] = p.pageBits
	be.PutUint32(b[40:], 0) // spare2
	be.PutUint32(b[44:], 0) // scatterOffset (0x20100)
	if p.teamID != "" {
		be.PutUint32(b[48:], uint32(teamOff)) // teamOffset (0x20200)
	}
	be.PutUint32(b[52:], 0) // spare3 (0x20300)
	be.PutUint64(b[56:], 0) // codeLimit64
	be.PutUint64(b[64:], uint64(p.execBase))  // execSegBase (0x20400)
	be.PutUint64(b[72:], uint64(p.execLimit)) // execSegLimit
	be.PutUint64(b[80:], p.execFlags)         // execSegFlags

	// identifier + optional team id (NUL-terminated)
	copy(b[idOff:], p.identifier)
	if p.teamID != "" {
		copy(b[teamOff:], p.teamID)
	}

	// special slots: -1 at hashOff-1*hashSize, … -nSpecial at the front.
	zero := make([]byte, hashSize)
	for i := 1; i <= nSpecial; i++ {
		dst := hashOff - i*hashSize
		if hv, ok := p.specialHashes[i]; ok && len(hv) == hashSize {
			copy(b[dst:], hv)
		} else {
			copy(b[dst:], zero)
		}
	}
	// code slots
	for i, hv := range p.codeHashes {
		copy(b[hashOff+i*hashSize:], hv)
	}
	return b
}

// cdHash returns the truncated (20-byte) CDHash of a serialised CodeDirectory,
// using the directory's own hash algorithm.
func cdHash(cd []byte, hashType uint8) []byte {
	h := hashFor(hashType).New()
	h.Write(cd)
	sum := h.Sum(nil)
	if len(sum) > cdHashLen {
		sum = sum[:cdHashLen]
	}
	return sum
}

// sortedSlots returns blob slots ordered for SuperBlob emission.
func sortBlobs(blobs []blob) {
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].slot < blobs[j].slot })
}