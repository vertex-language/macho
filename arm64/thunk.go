package arm64

import (
	"fmt"

	"github.com/vertex-language/macho/backend"
)

// thunkCode materializes an address in x16 and jumps to it. It is the stub
// sequence with the load removed: the target is known at link time, so there
// is no pointer to go through.
//
//	adrp x16, <target>@page
//	add  x16, x16, <target>@pageoff
//	br   x16
//
// x16 is the intra-procedure-call scratch register, which the AAPCS64 permits
// a linker-inserted veneer to clobber. Using any other register would corrupt
// a live value in the caller.
var thunkCode = [3]uint32{0x90000010, 0x91000210, 0xd61f0200}

// ThunkShape implements backend.Thunker.
//
// arm64 must implement Thunker, and the thunk-growth fixpoint in Link is not
// optional the way it is for an architecture whose branches reach across any
// plausible image. A BRANCH26 reaches 128 MiB, which real applications exceed.
func (b *Backend) ThunkShape() backend.ThunkShape { return b.thunk }

// WriteThunk writes one range-extension thunk.
//
// The ADRP reaches ±4 GiB, so a thunk placed anywhere in a normal image can
// reach any target in it. An image large enough to defeat that would need a
// second level of indirection through a pointer, which nothing here does — and
// the ADRP range check will report it rather than encoding silently.
func (b *Backend) WriteThunk(dst []byte, thunkAddr, target uint64) error {
	if len(dst) < ThunkSize {
		return fmt.Errorf("arm64: thunk needs %d bytes, got %d", ThunkSize, len(dst))
	}
	adrp, err := encodePage21(thunkCode[0], int64(pageOf(target))-int64(pageOf(thunkAddr)))
	if err != nil {
		return stubErr("thunk", err)
	}
	add, err := encodePageOff12(thunkCode[1], target)
	if err != nil {
		return stubErr("thunk", err)
	}
	put32(dst, 0, adrp)
	put32(dst, 1, add)
	put32(dst, 2, thunkCode[2])
	return nil
}