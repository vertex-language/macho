package binio

// LEB128 is load-bearing in Mach-O in a way it is not in ELF. The export trie,
// the classic rebase and bind opcode streams, LC_FUNCTION_STARTS, and
// LC_LINKER_OPTIMIZATION_HINT are all ULEB-encoded, so these are hot paths and
// their overflow behaviour is a correctness question, not a nicety.

// maxLEBBytes is the most bytes a 64-bit LEB128 value can occupy: nine groups
// of seven bits plus one for the remaining bit.
const maxLEBBytes = 10

// ULEB128 reads an unsigned LEB128 value.
//
// A value that does not fit in 64 bits is ErrOverflow rather than a silently
// truncated result, and an unterminated run is ErrTruncated.
func (c *Cursor) ULEB128() uint64 {
	if c.err != nil {
		return 0
	}
	var (
		result uint64
		shift  uint
	)
	for i := 0; ; i++ {
		if i >= maxLEBBytes {
			c.fail(ErrOverflow)
			return 0
		}
		b := c.U8()
		if c.err != nil {
			return 0
		}
		switch {
		case shift < 63:
			result |= uint64(b&0x7f) << shift
		case shift == 63:
			// Only bit 0 of this group still fits.
			if b&0x7f > 1 {
				c.fail(ErrOverflow)
				return 0
			}
			result |= uint64(b&0x01) << 63
		default:
			if b&0x7f != 0 {
				c.fail(ErrOverflow)
				return 0
			}
		}
		if b&0x80 == 0 {
			return result
		}
		shift += 7
	}
}

// SLEB128 reads a signed LEB128 value, sign-extending from the final group.
func (c *Cursor) SLEB128() int64 {
	if c.err != nil {
		return 0
	}
	var (
		result int64
		shift  uint
		b      uint8
	)
	for i := 0; ; i++ {
		if i >= maxLEBBytes {
			c.fail(ErrOverflow)
			return 0
		}
		b = c.U8()
		if c.err != nil {
			return 0
		}
		if shift < 64 {
			result |= int64(b&0x7f) << shift
		} else if b&0x7f != 0 && b&0x7f != 0x7f {
			// Past 64 bits only an all-zero or all-ones continuation is a
			// legal sign extension.
			c.fail(ErrOverflow)
			return 0
		}
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	if shift < 64 && b&0x40 != 0 {
		result |= -1 << shift
	}
	return result
}

// ULEB128 appends an unsigned LEB128 value.
func (b *Buf) ULEB128(v uint64) {
	for {
		c := uint8(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		b.U8(c)
		if v == 0 {
			return
		}
	}
}

// SLEB128 appends a signed LEB128 value.
func (b *Buf) SLEB128(v int64) {
	for {
		c := uint8(v & 0x7f)
		sign := c&0x40 != 0
		v >>= 7 // arithmetic shift
		if (v == 0 && !sign) || (v == -1 && sign) {
			b.U8(c)
			return
		}
		b.U8(c | 0x80)
	}
}

// ULEB128Size returns the encoded length of v, for sizing a table before
// building it. __LINKEDIT layout needs this: the offsets of later tables
// depend on the encoded size of earlier ones.
func ULEB128Size(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// SLEB128Size returns the encoded length of v.
func SLEB128Size(v int64) int {
	n := 0
	for {
		c := uint8(v & 0x7f)
		sign := c&0x40 != 0
		v >>= 7
		n++
		if (v == 0 && !sign) || (v == -1 && sign) {
			return n
		}
	}
}