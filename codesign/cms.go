package codesign

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// OIDs used in Apple's CMS code signatures.
var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	// Apple "cdhashes as plist" signed attribute.
	oidAppleCDHashPlist = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
)

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                issuerAndSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	// content absent for detached signatures
}

type outerContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// buildCMS produces the detached CMS SignedData wrapper for a CodeDirectory.
// cdBytes is the serialised primary CodeDirectory; its message digest and a
// plist of cdhashes are carried as signed attributes.
func buildCMS(id *Identity, cdBytes []byte, cdHashes [][]byte) ([]byte, error) {
	if id == nil || id.Key == nil {
		return nil, errors.New("codesign: nil identity")
	}

	// messageDigest = SHA-256 over the CodeDirectory content.
	h := crypto.SHA256.New()
	h.Write(cdBytes)
	md := h.Sum(nil)

	plist := cdHashesPlist(cdHashes)

	// Build the signed attributes set.
	attrs := []attribute{
		rawAttr(oidContentType, mustMarshal(oidData)),
		rawAttr(oidSigningTime, mustMarshal(time.Now().UTC())),
		rawAttr(oidMessageDigest, mustMarshal(md)),
		rawAttr(oidAppleCDHashPlist, mustMarshal(plist)),
	}

	// DER of the attributes as an explicit SET OF for signing (tag 0x31),
	// per RFC 5652 §5.4 — distinct from the [0] IMPLICIT tag in the message.
	signedAttrDER, err := marshalAttrSet(attrs)
	if err != nil {
		return nil, err
	}
	ah := crypto.SHA256.New()
	ah.Write(signedAttrDER)
	digestToSign := ah.Sum(nil)

	sig, sigAlg, err := signDigest(id, digestToSign)
	if err != nil {
		return nil, err
	}

	return assembleSignedData(id, signedAttrDER, sig, sigAlg)
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// cdHashesPlist encodes the cdhashes as an Apple plist XML array of <data>
// elements, as expected by the oidAppleCDHashPlist signed attribute.
func cdHashesPlist(cdHashes [][]byte) []byte {
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	sb.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ")
	sb.WriteString("\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	sb.WriteString("<plist version=\"1.0\">\n<array>\n")
	for _, h := range cdHashes {
		sb.WriteString("\t<data>")
		sb.WriteString(base64.StdEncoding.EncodeToString(h))
		sb.WriteString("</data>\n")
	}
	sb.WriteString("</array>\n</plist>")
	return []byte(sb.String())
}

// rawAttr wraps an already-DER-encoded attribute value in a one-element
// SET, producing an attribute ready for inclusion in signedAttrs.
func rawAttr(oid asn1.ObjectIdentifier, value []byte) attribute {
	setDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      value,
	})
	if err != nil {
		panic("codesign: rawAttr marshal: " + err.Error())
	}
	return attribute{
		Type:   oid,
		Values: asn1.RawValue{FullBytes: setDER},
	}
}

// mustMarshal DER-encodes v and panics on error.
func mustMarshal(v interface{}) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic("codesign: mustMarshal: " + err.Error())
	}
	return b
}

// marshalAttrSet encodes attrs as a DER SET (tag 0x31) for use as the
// signed-attributes input to the signature hash (RFC 5652 §5.4).
func marshalAttrSet(attrs []attribute) ([]byte, error) {
	var inner []byte
	for _, a := range attrs {
		b, err := asn1.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("codesign: marshal attribute %v: %w", a.Type, err)
		}
		inner = append(inner, b...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      inner,
	})
}

// signDigest signs the pre-hashed digest with the identity's key and returns
// the signature bytes along with the appropriate CMS AlgorithmIdentifier.
func signDigest(id *Identity, digest []byte) ([]byte, pkix.AlgorithmIdentifier, error) {
	var sigAlg pkix.AlgorithmIdentifier
	switch {
	case id.isECDSA():
		sigAlg = pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
	default: // RSA
		sigAlg = pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption}
	}
	sig, err := id.Key.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("codesign: sign: %w", err)
	}
	return sig, sigAlg, nil
}

// assembleSignedData builds the complete CMS SignedData DER and wraps it in
// the PKCS#7 BlobWrapper envelope.
//
// signedAttrDER must carry tag 0x31 (SET); this function re-tags it to 0xa0
// ([0] IMPLICIT) for the on-wire SignerInfo encoding per RFC 5652 §5.3.
func assembleSignedData(id *Identity, signedAttrDER, sig []byte, sigAlg pkix.AlgorithmIdentifier) ([]byte, error) {
	// Issuer name from the leaf certificate.
	issuerRaw, err := asn1.Marshal(id.Leaf.Issuer.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("codesign: marshal issuer: %w", err)
	}

	// RFC 5652 §5.3: signedAttrs in SignerInfo use [0] IMPLICIT (0xa0), not
	// the 0x31 SET tag used when computing the signature hash.
	implicitAttrs := make([]byte, len(signedAttrDER))
	copy(implicitAttrs, signedAttrDER)
	implicitAttrs[0] = 0xa0

	si := signerInfo{
		Version: 1,
		SID: issuerAndSerial{
			Issuer: asn1.RawValue{FullBytes: issuerRaw},
			Serial: id.Leaf.SerialNumber,
		},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		SignedAttrs:        asn1.RawValue{FullBytes: implicitAttrs},
		SignatureAlgorithm: sigAlg,
		Signature:          sig,
	}

	// Concatenate raw DER for leaf + any intermediates.
	var certBytes []byte
	for _, c := range append([]*x509.Certificate{id.Leaf}, id.Intermediates...) {
		certBytes = append(certBytes, c.Raw...)
	}

	sd := signedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: oidSHA256},
		},
		ContentInfo: contentInfo{ContentType: oidData},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certBytes,
		},
		SignerInfos: []signerInfo{si},
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("codesign: marshal SignedData: %w", err)
	}

	outer := outerContentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}
	outerDER, err := asn1.Marshal(outer)
	if err != nil {
		return nil, fmt.Errorf("codesign: marshal outer ContentInfo: %w", err)
	}

	return genericBlob(csmagicBlobWrapper, outerDER), nil
}