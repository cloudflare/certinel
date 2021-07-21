// Package pkitest provides a few utility functions shared across tests.
package pkitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"gotest.tools/v3/assert"
)

// CmpBigInt implements a functions that compares big.Ints and is
// compatible with cmp.Comparer.
func CmpBigInt(x, y *big.Int) bool {
	c := x.Cmp(y)
	if c == 0 {
		return true
	}
	return false
}

// NewPrivateKey is a test helper that creates a new ECDSA private key.
func NewPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err, "generating ecdsa private key")
	return priv
}

// EncodePrivateKey is a test heper that x509 encodes the provided
// ECDSA private key.
func EncodePrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	p, err := x509.MarshalECPrivateKey(key)
	assert.NilError(t, err, "marshaling x509")
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: p}
	return pem.EncodeToMemory(block)
}

// PemEncodeCertificate is a test helper that encodes the provided
// certificate with the public key derived from the ECDSA private key
// and encodes into PEM.
func PemEncodeCertificate(t *testing.T, cert x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	p, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	assert.NilError(t, err, "creating certificate")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: p}
	return pem.EncodeToMemory(block)
}
