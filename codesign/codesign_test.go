package codesign_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/codesign"
	"github.com/vertex-language/macho/link"
	"github.com/vertex-language/macho/obj"

	_ "github.com/vertex-language/macho/arm64"
)

// buildTrivialObject writes a minimal object defining _main: mov w0, #0; ret.
func buildTrivialObject(t *testing.T, target macho.Target) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := obj.NewWriter(&buf, obj.Options{
		Target: target,
		Flags:  macho.MH_SUBSECTIONS_VIA_SYMBOLS,
		Build:  target.Build(),
	})
	text := w.Section(obj.SectionHeader{
		Segment: macho.SEG_TEXT, Name: macho.SECT_TEXT,
		Type: macho.S_REGULAR, Attrs: macho.S_ATTR_PURE_INSTRUCTIONS, Align: 4,
	})
	text.Write([]byte{0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6})
	w.Symbol(obj.SymbolDef{Name: "_main", Type: macho.N_SECT, Ext: true, Section: text})
	if err := w.Close(); err != nil {
		t.Fatalf("obj.Writer.Close: %v", err)
	}
	return buf.Bytes()
}

const fakeLibSystem = `--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: '/usr/lib/libSystem.B.dylib'
current-version: 1
compatibility-version: 1
exports:
  - targets: [ arm64-macos ]
    symbols: [ _getpid ]
`

// buildSignedExecutable links a trivial program with this tree's own linker,
// which already reserves a code-signature slot and ad-hoc signs it. That
// makes the result a realistic input for codesign.SignFile to re-sign, the
// same way `codesign -f` would be used on a linker's output.
func buildSignedExecutable(t *testing.T) string {
	t.Helper()
	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	l, err := link.New(target)
	if err != nil {
		t.Fatalf("link.New: %v", err)
	}
	defer l.Close()

	objData := buildTrivialObject(t, target)
	if err := l.AddObject("t.o", objData); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := l.AddStub("libSystem", []byte(fakeLibSystem)); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	l.Options().Output = link.OutputExecute
	l.SetEntry("_main")

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	out, err := img.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	path := filepath.Join(t.TempDir(), "a.out")
	if err := os.WriteFile(path, out, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestSignFileAdHoc(t *testing.T) {
	path := buildSignedExecutable(t)

	res, err := codesign.SignFile(path, codesign.Options{Identifier: "com.example.test", Force: true})
	if err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	if res.Identifier != "com.example.test" {
		t.Errorf("Identifier = %q, want com.example.test", res.Identifier)
	}

	requireCodesignTool(t)
	out := runCodesign(t, "-dvvv", path)
	if !contains(out, "Identifier=com.example.test") {
		t.Errorf("codesign -dvvv did not report the new identifier:\n%s", out)
	}
	if !contains(out, "Signature=adhoc") {
		t.Errorf("codesign -dvvv did not report an ad-hoc signature:\n%s", out)
	}

	// --verify should accept the file we produced: a byte-for-byte check
	// that the CodeDirectory's page hashes actually match the file.
	verify := exec.Command("codesign", "--verify", "--strict", path)
	if out, err := verify.CombinedOutput(); err != nil {
		t.Errorf("codesign --verify failed: %v\n%s", err, out)
	}
}

func TestSignFileHardenedRuntime(t *testing.T) {
	path := buildSignedExecutable(t)

	if _, err := codesign.SignFile(path, codesign.Options{
		Identifier: "com.example.hardened",
		Hardened:   true,
		Force:      true,
	}); err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	requireCodesignTool(t)
	out := runCodesign(t, "-dvvv", path)
	if !contains(out, "flags=0x10001(runtime)") && !contains(out, "runtime") {
		t.Errorf("codesign -dvvv did not report the hardened runtime flag:\n%s", out)
	}
}

func TestSignFileEntitlements(t *testing.T) {
	path := buildSignedExecutable(t)

	plist := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.get-task-allow</key>
	<true/>
</dict>
</plist>
`)
	if _, err := codesign.SignFile(path, codesign.Options{
		Identifier:   "com.example.entitled",
		Entitlements: plist,
		Force:        true,
	}); err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	requireCodesignTool(t)
	out := runCodesign(t, "-d", "--entitlements", ":-", path)
	if !contains(out, "com.apple.security.get-task-allow") {
		t.Errorf("codesign did not report the embedded entitlement:\n%s", out)
	}
}

// TestSignFileRejectsUnreservedWithoutForce checks that a Mach-O with no
// LC_CODE_SIGNATURE slot needs Force before SignImage will rewrite it — an
// object file this tree's own obj.Writer produces is a convenient case that
// genuinely has no such slot, unlike anything link.Link produces.
func TestSignFileRejectsUnreservedWithoutForce(t *testing.T) {
	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	data := buildTrivialObject(t, target)

	if _, err := codesign.SignImage(data, codesign.Options{Identifier: "t"}); err == nil {
		t.Error("SignImage on an unreserved Mach-O succeeded without Force")
	}
}

func TestLoadIdentityPEMAndProductionSign(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeSelfSignedCert(t, certPath, keyPath)

	id, err := codesign.LoadIdentityPEM(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadIdentityPEM: %v", err)
	}

	path := buildSignedExecutable(t)
	if _, err := codesign.SignFile(path, codesign.Options{
		Identifier: "com.example.production",
		Identity:   id,
		Force:      true,
	}); err != nil {
		t.Fatalf("SignFile with a production identity: %v", err)
	}

	requireCodesignTool(t)
	// The signing chain is self-signed and untrusted, so --verify is
	// expected to fail on trust grounds; -dvvv only decodes what is there
	// and should show a non-ad-hoc signature without crashing.
	out := runCodesign(t, "-dvvv", path)
	if contains(out, "Signature=adhoc") {
		t.Errorf("expected a CMS signature, got an ad-hoc one:\n%s", out)
	}
}

func requireCodesignTool(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("codesign CLI is macOS-only")
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skip("codesign CLI not found on PATH")
	}
}

func runCodesign(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("codesign", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("codesign %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// writeSelfSignedCert generates a throwaway self-signed EC cert/key pair for
// exercising the production (CMS) signing path's plumbing. It proves the code
// path runs correctly, not that macOS would trust the result.
func writeSelfSignedCert(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "macho test signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("WriteFile(cert): %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}
}
