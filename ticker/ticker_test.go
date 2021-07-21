package ticker

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/certinel/internel/pkitest"
	"github.com/google/go-cmp/cmp"
	"github.com/jonboulle/clockwork"
	"golang.org/x/sync/errgroup"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/fs"
	"gotest.tools/v3/poll"
)

func TestTicker(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	clock := clockwork.NewFakeClock()

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

	watcher.clock = clock

	cert, err := watcher.GetCertificate(nil)
	assert.NilError(t, err)
	assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(1), cmp.Comparer(pkitest.CmpBigInt))

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return watcher.Start(gctx)
	})

	fs.Apply(t, dir, fs.WithFile("my.crt", "", fs.WithBytes(
		pkitest.PemEncodeCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(10000),
		}, pk),
	)))

	clock.BlockUntil(1)
	clock.Advance(1 * time.Minute)

	poll.WaitOn(t, func(t poll.LogT) poll.Result {
		cert, err := watcher.GetCertificate(nil)
		if err != nil {
			return poll.Error(err)
		}

		return poll.Compare(is.DeepEqual(cert.Leaf.SerialNumber, big.NewInt(10000), cmp.Comparer(pkitest.CmpBigInt)))
	})

	cancel()
	assert.ErrorType(t, g.Wait(), context.Canceled)
}
