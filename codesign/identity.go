package codesign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Identity is a certificate + private key used for production CMS signing,
// plus any intermediate certs to embed in the chain.
type Identity struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
	Key           crypto.Signer
}

// LoadIdentityPEM reads a leaf cert (+ optional intermediates) and a private
// key from PEM files. PKCS#12 (.p12) loading is intentionally out of scope to
// keep the package pure-stdlib; convert with `openssl pkcs12` first.
func LoadIdentityPEM(certPath, keyPath string) (*Identity, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return parseIdentity(certPEM, keyPEM)
}

func parseIdentity(certPEM, keyPEM []byte) (*Identity, error) {
	id := &Identity{}
	rest := certPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		if id.Leaf == nil {
			id.Leaf = c
		} else {
			id.Intermediates = append(id.Intermediates, c)
		}
	}
	if id.Leaf == nil {
		return nil, errors.New("codesign: no certificate found")
	}

	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("codesign: no PEM private key found")
	}
	key, err := parseKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	id.Key = key
	return id, nil
}

func parseKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("codesign: PKCS#8 key is not a signer")
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("codesign: unsupported private key format")
}

// keyAlgo returns whether the identity key is RSA or ECDSA, for CMS algorithm
// identifier selection.
func (id *Identity) isRSA() bool  { _, ok := id.Key.(*rsa.PrivateKey); return ok }
func (id *Identity) isECDSA() bool { _, ok := id.Key.(*ecdsa.PrivateKey); return ok }

var _ = fmt.Sprintf