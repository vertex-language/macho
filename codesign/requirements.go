package codesign

import "encoding/binary"

// Requirement expression opcodes (subset, from requirement.h).
const (
	opFalse              uint32 = 0
	opTrue               uint32 = 1
	opIdent              uint32 = 2
	opAppleAnchor        uint32 = 3
	opAnd                uint32 = 6
	opOr                 uint32 = 7
	opAppleGenericAnchor uint32 = 15
)

// Requirement set types.
const reqDesignated uint32 = 3

// emptyRequirements builds a requirements set with zero entries — what ad-hoc
// signing emits. magic 0xfade0c01, length 12, count 0.
func emptyRequirements() []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b[0:], csmagicRequirements)
	binary.BigEndian.PutUint32(b[4:], 12)
	binary.BigEndian.PutUint32(b[8:], 0)
	return b
}

// designatedRequirement compiles `identifier "<id>" and anchor apple generic`
// into a single Requirement blob, then wraps it in a one-entry requirements
// set. This is the common implicit DR for Developer ID code.
func designatedRequirement(id string) []byte {
	// expr = And( Ident(id), AppleGenericAnchor )
	var expr []byte
	expr = appendU32(expr, opAnd)
	expr = appendU32(expr, opIdent)
	expr = appendReqString(expr, id)
	expr = appendU32(expr, opAppleGenericAnchor)

	// Requirement blob: magic, length, kind(1=expr), expr
	reqBody := append(appendU32(nil, 1), expr...)
	req := genericBlob(csmagicRequirement, reqBody)

	// Requirements set: magic, length, count, [type, offset], req
	const hdr = 12 + 8
	total := hdr + len(req)
	set := make([]byte, total)
	be := binary.BigEndian
	be.PutUint32(set[0:], csmagicRequirements)
	be.PutUint32(set[4:], uint32(total))
	be.PutUint32(set[8:], 1)
	be.PutUint32(set[12:], reqDesignated)
	be.PutUint32(set[16:], hdr)
	copy(set[hdr:], req)
	return set
}

func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// appendReqString writes a length-prefixed string padded to a 4-byte boundary.
func appendReqString(b []byte, s string) []byte {
	b = appendU32(b, uint32(len(s)))
	b = append(b, s...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}