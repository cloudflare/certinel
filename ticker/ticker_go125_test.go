//go:build go1.25

package ticker

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cloudflare/certinel/internel/pkitest"
	"github.com/google/go-cmp/cmp"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/fs"
)

func TestTickerSync(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		pk := pkitest.NewPrivateKey(t)
		pemPK := pkitest.EncodePrivateKey(t, pk)

		dir := fs.NewDir(t, "test-ticker",
			fs.WithFile("my.key", "", fs.WithBytes(pemPK)),
			fs.WithFile("my.crt", "", fs.WithBytes(
				pkitest.PemEncodeCertificate(t, x509.Certificate{
					SerialNumber: big.NewInt(1),
				}, pk),
			)),
		)
		defer dir.Remove()

		watcher, err := New(dir.Join("my.crt"), dir.Join("my.key"), 1*time.Minute)
		assert.NilError(t, err)

		cert, err := watcher.GetCertificate(nil)
		assert.NilError(t, err)
		assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(1), cmp.Comparer(pkitest.CmpBigInt))

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()

		var watcherErr error
		go func() {
			watcherErr = watcher.Start(ctx)
		}()

		// Ensure the watcher didn't return an error during startup.
		time.Sleep(30 * time.Second)
		assert.NilError(t, watcherErr)

		fs.Apply(t, dir, fs.WithFile("my.crt", "", fs.WithBytes(
			pkitest.PemEncodeCertificate(t, x509.Certificate{
				SerialNumber: big.NewInt(10000),
			}, pk),
		)))

		// After the first tick the watcher should have observed a new certificate
		time.Sleep(1 * time.Minute)
		synctest.Wait()
		assert.NilError(t, watcherErr)

		cert, err = watcher.GetCertificate(nil)
		assert.NilError(t, err)
		assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(10000), cmp.Comparer(pkitest.CmpBigInt))

		// Wait out the rest of the timeout
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.ErrorIs(t, watcherErr, context.DeadlineExceeded)
	})
}
