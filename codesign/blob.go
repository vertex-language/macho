package codesign

import "encoding/binary"

// blob is one component (CodeDirectory, requirements, entitlements, CMS…)
// already serialised into its on-disk magic+length+data form.
type blob struct {
	slot uint32 // SuperBlob index type
	data []byte // full blob bytes, starting with its own magic
}

// genericBlob wraps arbitrary payload in the magic+length envelope shared by
// entitlements, requirements wrappers, and the CMS wrapper.
func genericBlob(magic uint32, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:], magic)
	binary.BigEndian.PutUint32(out[4:], uint32(8+len(payload)))
	copy(out[8:], payload)
	return out
}

// assembleSuperBlob lays out the SuperBlob: header, sorted index, then blobs.
// Slots must be sorted ascending by type (the kernel relies on this for the
// CodeDirectory appearing first).
func assembleSuperBlob(blobs []blob) []byte {
	// header(12) + index(8*n) + sum(blob lengths)
	const hdr = 12
	idx := 8 * len(blobs)
	body := hdr + idx
	total := body
	for _, b := range blobs {
		total += len(b.data)
	}

	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:], csmagicEmbeddedSignature)
	binary.BigEndian.PutUint32(out[4:], uint32(total))
	binary.BigEndian.PutUint32(out[8:], uint32(len(blobs)))

	cursor := body
	for i, b := range blobs {
		ix := hdr + i*8
		binary.BigEndian.PutUint32(out[ix:], b.slot)
		binary.BigEndian.PutUint32(out[ix+4:], uint32(cursor))
		copy(out[cursor:], b.data)
		cursor += len(b.data)
	}
	return out
}