package pollwatcher_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/pantheon-systems/certinel/pollwatcher"
	"github.com/stretchr/testify/assert"
)

func generateKeyAndCert(keyFile, certFile string) error {
	template := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          big.NewInt(1234),
		Subject: pkix.Name{
			Country:      []string{"Earth"},
			Organization: []string{"Mother Nature"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(5, 5, 5),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	publickey := &privatekey.PublicKey

	// create a self-signed certificate.
	cert, err := x509.CreateCertificate(rand.Reader, template, template, publickey, privatekey)
	if err != nil {
		fmt.Println(err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", certFile, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return fmt.Errorf("failed to write data to %s: %s", certFile, err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %s", certFile, err)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %s", keyFile, err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}); err != nil {
		return fmt.Errorf("failed to write data to %s: %s", keyFile, err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("error closing %s: %s", keyFile, err)
	}

	return nil
}
func TestPollWatcher(t *testing.T) {
	key := "tls.key"
	crt := "tls.crt"

	if err := generateKeyAndCert(key, crt); err != nil {
		t.Fatal(err)
	}

	defer func() {
		os.Remove(key)
		os.Remove(crt)
	}()

	interval := 1 * time.Second
	w := pollwatcher.New(crt, key, interval)
	defer w.Close()
	certCh, _ := w.Watch()

	initialCert := <-certCh

	if err := generateKeyAndCert(key, crt); err != nil {
		t.Fatal(err)
	}

	newCert := <-certCh

	time.Sleep(interval + 1)

	assert.NotEqual(t, initialCert, newCert, "Expected different cert but got same cert")
}
