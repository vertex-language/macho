package codesign

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SignResult is returned by SignFile and describes the outcome of a successful
// signing operation so that the caller can print a rich confirmation line.
type SignResult struct {
	Format     string // e.g. "Mach-O thin (arm64)" or "Mach-O universal (arm64 x86_64)"
	Identifier string // the signing identifier embedded in the CodeDirectory
}

// Options is the clean, codesign-inspired API surface.
type Options struct {
	Identifier   string    // CodeDirectory ident; default: file base name
	TeamID       string    // optional team identifier
	Identity     *Identity // nil => ad-hoc; non-nil => production CMS
	Force        bool      // overwrite an existing signature (codesign -f)
	Hardened     bool      // set CS_RUNTIME
	Entitlements []byte    // raw XML entitlements plist (optional)
	HashType     uint8     // 0 => SHA-256
	Logger       *Logger   // nil => silent at all levels
}

// logger returns the Options logger; it is always safe to call — a nil Logger
// silently drops all output.
func (o *Options) logger() *Logger { return o.Logger }

// SignFile signs the Mach-O at path in place via an atomic rename and returns
// a description of the result.
//
// The rename strategy is critical on Apple Silicon: the kernel caches code
// signatures per vnode.  Overwriting in-place can leave a stale cached
// signature; rename(2) atomically replaces the directory entry and forces the
// kernel to evaluate the new signature on the next exec.
func SignFile(path string, opts Options) (SignResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return SignResult{}, err
	}
	if opts.Identifier == "" {
		opts.Identifier = filepath.Base(path)
	}

	l := opts.logger()
	l.V1("%s: reading Mach-O (%d bytes)", path, len(raw))

	// Parse once here so we can build the format string without a second parse
	// inside signImage.
	img, err := Parse(raw)
	if err != nil {
		return SignResult{}, err
	}

	format := img.FormatString()
	l.V1("%s: %s", path, format)
	l.V2("Identifier=%s", opts.Identifier)
	l.V2("Format=%s", format)
	if opts.TeamID != "" {
		l.V2("TeamIdentifier=%s", opts.TeamID)
	} else {
		l.V2("TeamIdentifier=not set")
	}
	if len(opts.Entitlements) > 0 {
		l.V2("Entitlements=%d bytes (XML plist)", len(opts.Entitlements))
	} else {
		l.V2("Entitlements=none")
	}
	if opts.Hardened {
		l.V2("HardenedRuntime=yes (CS_RUNTIME)")
	}
	if opts.Identity == nil {
		l.V2("SigningMode=ad-hoc")
	} else {
		l.V2("SigningMode=production CMS  leaf=%s", opts.Identity.Leaf.Subject.CommonName)
	}

	out, err := signImage(img, opts)
	if err != nil {
		return SignResult{}, err
	}

	info, _ := os.Stat(path)
	mode := os.FileMode(0o755)
	if info != nil {
		mode = info.Mode()
	}

	tmp := path + ".__codesigner_tmp"
	if err := os.WriteFile(tmp, out, mode); err != nil {
		return SignResult{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return SignResult{}, err
	}

	return SignResult{Format: format, Identifier: opts.Identifier}, nil
}

// SignImage signs every slice of a (fat or thin) image and returns new bytes.
func SignImage(raw []byte, opts Options) ([]byte, error) {
	img, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return signImage(img, opts)
}

// signImage is the internal implementation that operates on an already-parsed
// Image to avoid double parsing in SignFile.
func signImage(img *Image, opts Options) ([]byte, error) {
	l := opts.logger()
	if img.isFat {
		l.V2("Universal binary: %d architecture slices", len(img.Slices))
	}
	for _, sl := range img.Slices {
		if !sl.hasReservedSignatureSpace() && !opts.Force {
			return nil, fmt.Errorf("codesign: slice has no LC_CODE_SIGNATURE; "+
				"re-link, or pass -f to allow a full rewrite")
		}
		if err := signSlice(sl, opts); err != nil {
			return nil, err
		}
	}
	return img.serialize()
}

func (s *Slice) hashType(opts Options) uint8 {
	if opts.HashType != 0 {
		return opts.HashType
	}
	return csHashTypeSHA256
}

// signSlice computes all hashes, assembles the SuperBlob, and writes it into
// the slice.  All verbosity output is gated on opts.Logger.
func signSlice(s *Slice, opts Options) error {
	l := opts.logger()
	tTotal := time.Now()

	ht := s.hashType(opts)
	codeLimit := s.signatureRegionStart()

	// -vvv: dump the full Mach-O header and every load command first.
	s.LogHeader(l)

	// -v: one-line summary of what we are about to sign.
	l.V1("  arch:           %s", s.ArchString())
	l.V1("  identifier:     %s", opts.Identifier)
	l.V1("  hash type:      %s", hashTypeName(ht))

	// CS flags.
	var flags uint32
	if opts.Identity == nil {
		flags = csAdhoc
	}
	if opts.Hardened {
		flags |= csRuntime
	}

	var execFlags uint64
	if s.isMain {
		execFlags = csExecSegMainBinary
	}

	// -vv: CodeDirectory parameters.
	l.V2("  codeLimit:      %d  (0x%x)", codeLimit, codeLimit)
	l.V2("  csFlags:        0x%08x  (%s)", flags, csFlagsStr(flags))
	l.V2("  execSegBase:    0x%016x", s.textOff)
	l.V2("  execSegLimit:   0x%016x  (%d bytes)", s.textSize, s.textSize)
	l.V2("  execSegFlags:   0x%016x  (%s)", execFlags, execSegFlagsStr(execFlags))
	l.V2("  isMainBinary:   %v", s.isMain)

	// ── Requirements ──────────────────────────────────────────────────────────
	special := map[int][]byte{}
	var components []blob

	var reqs []byte
	if opts.Identity != nil {
		reqs = designatedRequirement(opts.Identifier)
	} else {
		reqs = emptyRequirements()
	}
	reqHash := hashBlob(reqs, ht)
	special[2] = reqHash
	components = append(components, blob{slot: csslotRequirements, data: reqs})
	l.V2("  requirements:   %d bytes  (special slot -2)", len(reqs))
	l.V3("    hash:         %s", hex.EncodeToString(reqHash))

	// ── Entitlements ──────────────────────────────────────────────────────────
	if len(opts.Entitlements) > 0 {
		ent := xmlEntitlements(opts.Entitlements)
		entHash := hashBlob(ent, ht)
		special[5] = entHash
		components = append(components, blob{slot: csslotEntitlements, data: ent})
		l.V2("  entitlements:   %d bytes  (special slot -5)", len(ent))
		l.V3("    hash:         %s", hex.EncodeToString(entHash))
	}

	// ── PRE-PASS: Determine Signature Size ────────────────────────────────────
	// We must patch the Mach-O header before hashing Page 0. We build a dummy
	// CodeDirectory using zero-filled hashes to find the exact final size.
	nPages := int((codeLimit + pageSize - 1) / pageSize)
	dummyHashes := make([][]byte, nPages)
	hashSize := int(hashFor(ht).Size())
	for i := range dummyHashes {
		dummyHashes[i] = make([]byte, hashSize)
	}

	dummyCD := buildCodeDirectory(cdParams{
		identifier:    opts.Identifier,
		teamID:        opts.TeamID,
		flags:         flags,
		hashType:      ht,
		pageBits:      pageSizeBits,
		codeLimit:     codeLimit,
		execBase:      s.textOff,
		execLimit:     s.textSize,
		execFlags:     execFlags,
		codeHashes:    dummyHashes,
		specialHashes: special,
	})

	dummyAll := append([]blob{{slot: csslotCodeDirectory, data: dummyCD}}, components...)

	if opts.Identity != nil {
		// For production CMS, generate a dummy signature to reserve the correct byte length.
		dummyCDHash := cdHash(dummyCD, ht)
		dummyCMS, err := buildCMS(opts.Identity, dummyCD, [][]byte{dummyCDHash})
		if err != nil {
			return err
		}
		dummyAll = append(dummyAll, blob{slot: csslotSignature, data: dummyCMS})
	}

	sortBlobs(dummyAll)
	expectedSigSize := len(assembleSuperBlob(dummyAll))

	// Patch the Mach-O header BEFORE hashing!
	s.PatchHeaders(expectedSigSize, codeLimit)

	// ── Code-page hashes ──────────────────────────────────────────────────────
	tHash := time.Now()
	codeHashes, err := s.pageHashes(codeLimit, ht)
	if err != nil {
		return err
	}
	hashElapsed := time.Since(tHash)

	l.V2("  codeSlots:      %d pages × %d bytes", len(codeHashes), pageSize)
	l.V3("  hashing time:   %v", hashElapsed)

	if l.Active(VerbosityV3) {
		l.Section("Code Page Hashes")
		const maxShow = 6
		for i, h := range codeHashes {
			switch {
			case i < maxShow:
				l.V3("    [%5d]: %s", i, hex.EncodeToString(h))
			case i == maxShow && len(codeHashes) > maxShow+1:
				l.V3("    ... (%d pages omitted) ...", len(codeHashes)-maxShow-1)
			case i == len(codeHashes)-1:
				l.V3("    [%5d]: %s  (last page, %d bytes)",
					i, hex.EncodeToString(h), codeLimit%pageSize)
			}
		}
	}

	// ── CodeDirectory ─────────────────────────────────────────────────────────
	// Compute nSpecial (highest occupied special slot index) for the log line.
	nSpecial := 0
	for k := range special {
		if k > nSpecial {
			nSpecial = k
		}
	}

	cd := buildCodeDirectory(cdParams{
		identifier:    opts.Identifier,
		teamID:        opts.TeamID,
		flags:         flags,
		hashType:      ht,
		pageBits:      pageSizeBits,
		codeLimit:     codeLimit,
		execBase:      s.textOff,
		execLimit:     s.textSize,
		execFlags:     execFlags,
		codeHashes:    codeHashes,
		specialHashes: special,
	})

	cdh := cdHash(cd, ht)
	primary := blob{slot: csslotCodeDirectory, data: cd}

	l.V2("  CodeDirectory:  v%05x  size=%d  flags=0x%x(%s)  hashes=%d+%d  location=embedded",
		csSupportsExecSeg, len(cd), flags, csFlagsStr(flags), len(codeHashes), nSpecial)
	l.V2("  CDHash:         %s  (%s, truncated to %d bytes)",
		hex.EncodeToString(cdh), hashTypeName(ht), cdHashLen)

	if l.Active(VerbosityV3) {
		l.Section("Special Slot Hashes")
		slotNames := map[int]string{
			1: "Info.plist",
			2: "Requirements",
			3: "ResourceDirectory",
			4: "Application",
			5: "Entitlements",
			6: "RepSpecific",
			7: "DEREntitlements",
		}
		for i := 1; i <= nSpecial; i++ {
			name := slotNames[i]
			if name == "" {
				name = fmt.Sprintf("slot%d", i)
			}
			if h, ok := special[i]; ok {
				l.V3("    slot -%d  %-18s  %s", i, "("+name+")", hex.EncodeToString(h))
			} else {
				l.V3("    slot -%d  %-18s  (zeroed — not present)", i, "("+name+")")
			}
		}
	}

	// ── CMS signature (production only) ───────────────────────────────────────
	all := append([]blob{primary}, components...)

	if opts.Identity != nil {
		l.V2("  CMS:            building SignedData...")
		tCMS := time.Now()
		cms, err := buildCMS(opts.Identity, cd, [][]byte{cdh})
		if err != nil {
			return err
		}
		all = append(all, blob{slot: csslotSignature, data: cms})
		l.V2("  CMS:            %d bytes  (elapsed %v)", len(cms), time.Since(tCMS))
	}

	// ── SuperBlob ──────────────────────────────────────────────────────────────
	sortBlobs(all)
	super := assembleSuperBlob(all)

	l.V2("  SuperBlob:      %d bytes total  (%d blobs)", len(super), len(all))

	if l.Active(VerbosityV3) {
		l.Section("SuperBlob Layout")
		// Recompute offsets to match assembleSuperBlob: header(12) + index(8*n) + blobs.
		cursor := 12 + 8*len(all)
		for _, b := range all {
			l.V3("    slot=0x%08x  %-20s  offset=%-8d  size=%d",
				b.slot, "("+superBlobSlotName(b.slot)+")", cursor, len(b.data))
			cursor += len(b.data)
		}
	}

	// ── Embed ──────────────────────────────────────────────────────────────────
	// At this point, embedSignature should only be appending the bytes,
	// as s.PatchHeaders() already updated the LC_CODE_SIGNATURE & __LINKEDIT sizes.
	if err := s.embedSignature(super, codeLimit); err != nil {
		return err
	}

	l.V2("  SignatureSize:  %d bytes", len(super))
	l.V3("  total elapsed:  %v", time.Since(tTotal))

	return nil
}

// pageHashes hashes each 4 KiB page of the slice over [0, codeLimit).
// Each page is hashed over its exact bytes; the final short page is NOT
// zero-padded — this matches Apple's codesign, the Darwin linker, and the
// kernel's page validation.
func (s *Slice) pageHashes(codeLimit int64, ht uint8) ([][]byte, error) {
	h := hashFor(ht).New()
	var out [][]byte
	for off := int64(0); off < codeLimit; off += pageSize {
		end := off + pageSize
		if end > codeLimit {
			end = codeLimit
		}
		h.Reset()
		h.Write(s.Bytes[off:end])
		out = append(out, h.Sum(nil))
	}
	return out, nil
}

func hashBlob(b []byte, ht uint8) []byte {
	h := hashFor(ht).New()
	h.Write(b)
	return h.Sum(nil)
}

// ── String helpers ────────────────────────────────────────────────────────────

func csFlagsStr(f uint32) string {
	var parts []string
	if f&csAdhoc != 0 {
		parts = append(parts, "adhoc")
	}
	if f&csRuntime != 0 {
		parts = append(parts, "runtime")
	}
	if f&csLinkerSigned != 0 {
		parts = append(parts, "linker-signed")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func execSegFlagsStr(f uint64) string {
	var parts []string
	if f&csExecSegMainBinary != 0 {
		parts = append(parts, "MAIN_BINARY")
	}
	if f&csExecSegAllowUnsigned != 0 {
		parts = append(parts, "ALLOW_UNSIGNED")
	}
	if f&csExecSegJIT != 0 {
		parts = append(parts, "JIT")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

func hashTypeName(t uint8) string {
	switch t {
	case csHashTypeSHA1:
		return "SHA-1 (1)"
	case csHashTypeSHA256:
		return "SHA-256 (2)"
	case csHashTypeSHA256Truncated:
		return "SHA-256/Truncated (3)"
	case csHashTypeSHA384:
		return "SHA-384 (4)"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}

func superBlobSlotName(slot uint32) string {
	switch slot {
	case csslotCodeDirectory:
		return "CodeDirectory"
	case csslotInfoSlot:
		return "Info.plist"
	case csslotRequirements:
		return "Requirements"
	case csslotResourceDir:
		return "ResourceDir"
	case csslotApplication:
		return "Application"
	case csslotEntitlements:
		return "Entitlements"
	case csslotRepSpecific:
		return "RepSpecific"
	case csslotDEREntitlements:
		return "DEREntitlements"
	case csslotSignature:
		return "CMS Signature"
	default:
		return fmt.Sprintf("unknown(0x%x)", slot)
	}
}

// Blank imports used as compile-time sentinels.
var _ = sha256.Size
var _ = errors.New