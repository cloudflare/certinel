package fswatcher_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/certinel/fswatcher"
	"github.com/google/go-cmp/cmp"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/fs"
)

func TestWatch_Symlink(t *testing.T) {
	pk := generatePrivateKey(t)
	pemPK := encodePrivateKey(t, pk)

	dir := fs.NewDir(t, "test-symlink",
		fs.WithDir(".first", fs.WithFile("my.crt", "", fs.WithBytes(encodeCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(1),
		}, pk)))),
		fs.WithDir(".second", fs.WithFile("my.crt", "", fs.WithBytes(encodeCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(2),
		}, pk)))),
		fs.WithFile("my.key", "", fs.WithBytes(pemPK)),
		fs.WithSymlink("my.crt", ".first/my.crt"),
	)
	defer dir.Remove()

	watcher, err := fswatcher.New(dir.Join("my.crt"), dir.Join("my.key"))
	assert.NilError(t, err)

	tlsChan, errChan := watcher.Watch()
	select {
	case <-time.After(1 * time.Second):
		t.Fatalf("did not observe a certificate change in time")
	case err := <-errChan:
		assert.NilError(t, err, "got an error while reading certificate 1")
	case cert := <-tlsChan:
		assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(1), cmp.Comparer(cmpBigInt))
	}

	fs.Apply(t, dir, fs.WithSymlink(".my.new.crt", ".second/my.crt"))
	err = os.Rename(dir.Join(".my.new.crt"), dir.Join("my.crt"))
	assert.NilError(t, err)

	select {
	case <-time.After(1 * time.Second):
		t.Fatalf("did not observe a certificate change in time")
	case err := <-errChan:
		assert.NilError(t, err, "got an error while reading certificate 2")
	case cert := <-tlsChan:
		assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(2), cmp.Comparer(cmpBigInt))
	}
}

func TestWatch_Replacement(t *testing.T) {
	pk := generatePrivateKey(t)
	pemPK := encodePrivateKey(t, pk)

	dir := fs.NewDir(t, "test-replacement",
		fs.WithFile("my.key", "", fs.WithBytes(pemPK)),
		fs.WithFile("my.crt", "", fs.WithBytes(encodeCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(9999),
		}, pk))),
	)
	defer dir.Remove()

	watcher, err := fswatcher.New(dir.Join("my.crt"), dir.Join("my.key"))
	assert.NilError(t, err)

	tlsChan, errChan := watcher.Watch()
	select {
	case <-time.After(1 * time.Second):
		t.Fatalf("did not observe a certificate change in time")
	case err := <-errChan:
		assert.NilError(t, err, "got an error while reading certificate 1")
	case cert := <-tlsChan:
		assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(9999), cmp.Comparer(cmpBigInt))
	}

	fs.Apply(t, dir, fs.WithFile("cert.new", "", fs.WithBytes(encodeCertificate(t, x509.Certificate{
		SerialNumber: big.NewInt(10000),
	}, pk))))
	err = os.Rename(dir.Join("cert.new"), dir.Join("my.crt"))
	assert.NilError(t, err)

	select {
	case <-time.After(1 * time.Second):
		t.Fatalf("did not observe a certificate change in time")
	case err := <-errChan:
		assert.NilError(t, err, "got an error while reading certificate 2")
	case cert := <-tlsChan:
		assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(10000), cmp.Comparer(cmpBigInt))
	}
}

func TestClose(t *testing.T) {
	pk := generatePrivateKey(t)
	pemPK := encodePrivateKey(t, pk)
	cert := encodeCertificate(t, x509.Certificate{
		SerialNumber: big.NewInt(9001),
	}, pk)

	dir := fs.NewDir(t, "test-close",
		fs.WithFile("my.key", "", fs.WithBytes(pemPK)),
		fs.WithFile("my.crt", "", fs.WithBytes(cert)),
	)
	defer dir.Remove()

	watcher, err := fswatcher.New(dir.Join("my.crt"), dir.Join("my.key"))
	assert.NilError(t, err)

	tlsChan, errChan := watcher.Watch()

	select {
	case <-time.After(1 * time.Second):
		t.Fatalf("expected a certificate error")
	case err := <-errChan:
		assert.NilError(t, err, "got an error while reading certificate")
	case cert := <-tlsChan:
		assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(9001), cmp.Comparer(cmpBigInt))
	}

	err = watcher.Close()
	assert.NilError(t, err)

	// Ensure that the error channel has been closed.
	select {
	default:
		t.Errorf("default case on select of channel expected to be closed")
	case _, ok := <-errChan:
		assert.Assert(t, !ok, "receive on channel expected to be closed")
	}

	// Ensure that the tls channel has been closed.
	select {
	default:
		t.Errorf("default case on select of channel expected to be closed")
	case _, ok := <-tlsChan:
		assert.Assert(t, !ok, "receive on channel expected to be closed")
	}

	// Subsequent calls to Close return nil and do not panic.
	assert.NilError(t, watcher.Close())

	// Heavy cycling of fswatchers does not cause a race condition.
	for i := 0; i < 10; i++ {
		// Create a new watch.
		w, err := fswatcher.New(dir.Join("my.crt"), dir.Join("my.key"))
		assert.NilError(t, err)

		// Start the watch and drain channels.
		tlsCh, errCh := w.Watch()
		go func() {
			for range tlsCh {
			}
		}()
		go func() {
			for range errCh {
			}
		}()

		// Immediately close the watch, e.g. because a Dial failed.
		assert.NilError(t, w.Close())
	}
}

func cmpBigInt(x, y *big.Int) bool {
	c := x.Cmp(y)
	if c == 0 {
		return true
	}
	return false
}

func generatePrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err, "generating ecdsa private key")
	return priv
}

func encodePrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	p, err := x509.MarshalECPrivateKey(key)
	assert.NilError(t, err, "marshaling x509")
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: p}
	return pem.EncodeToMemory(block)
}

func encodeCertificate(t *testing.T, cert x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	p, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	assert.NilError(t, err, "creating certificate")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: p}
	return pem.EncodeToMemory(block)
}
