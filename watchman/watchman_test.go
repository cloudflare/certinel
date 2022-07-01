package watchman

import (
	"context"
	"crypto/x509"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/certinel/internel/pkitest"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/sync/errgroup"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/fs"
	"gotest.tools/v3/poll"
)

func TestWatcher_Symlink(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	pk := pkitest.NewPrivateKey(t)
	pemPK := pkitest.EncodePrivateKey(t, pk)

	dir := fs.NewDir(t, "test-symlink",
		fs.WithDir(".first", fs.WithFile("my.crt", "", fs.WithBytes(
			pkitest.PemEncodeCertificate(t, x509.Certificate{
				SerialNumber: big.NewInt(1),
			}, pk),
		))),
		fs.WithDir(".second", fs.WithFile("my.crt", "", fs.WithBytes(
			pkitest.PemEncodeCertificate(t, x509.Certificate{
				SerialNumber: big.NewInt(2),
			}, pk),
		))),
		fs.WithFile("my.key", "", fs.WithBytes(pemPK)),
		fs.WithSymlink("my.crt", ".first/my.crt"),
	)
	defer dir.Remove()

	watcher, err := New(dir.Join("my.crt"), dir.Join("my.key"))
	assert.NilError(t, err)

	cert, err := watcher.GetCertificate(nil)
	assert.NilError(t, err)
	assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(1), cmp.Comparer(pkitest.CmpBigInt))

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return watcher.Start(gctx)
	})
	<-time.After(100 * time.Millisecond)

	fs.Apply(t, dir, fs.WithSymlink(".my.new.crt", ".second/my.crt"))
	err = os.Rename(dir.Join(".my.new.crt"), dir.Join("my.crt"))
	assert.NilError(t, err)

	poll.WaitOn(t, func(t poll.LogT) poll.Result {
		cert, err := watcher.GetCertificate(nil)
		if err != nil {
			return poll.Error(err)
		}

		return poll.Compare(is.DeepEqual(cert.Leaf.SerialNumber, big.NewInt(2), cmp.Comparer(pkitest.CmpBigInt)))
	})

	cancel()
	assert.ErrorType(t, g.Wait(), context.Canceled)
}

func TestWatcher_Replacement(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	pk := pkitest.NewPrivateKey(t)
	pemPK := pkitest.EncodePrivateKey(t, pk)

	dir := fs.NewDir(t, "test-replacement",
		fs.WithFile("my.key", "", fs.WithBytes(pemPK)),
		fs.WithFile("my.crt", "", fs.WithBytes(
			pkitest.PemEncodeCertificate(t, x509.Certificate{
				SerialNumber: big.NewInt(9999),
			}, pk),
		)),
	)
	defer dir.Remove()

	watcher, err := New(dir.Join("my.crt"), dir.Join("my.key"))
	assert.NilError(t, err)

	cert, err := watcher.GetCertificate(nil)
	assert.NilError(t, err)
	assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(9999), cmp.Comparer(pkitest.CmpBigInt))

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return watcher.Start(gctx)
	})
	<-time.After(100 * time.Millisecond)

	fs.Apply(t, dir, fs.WithFile("cert.new", "", fs.WithBytes(
		pkitest.PemEncodeCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(10000),
		}, pk),
	)))
	err = os.Rename(dir.Join("cert.new"), dir.Join("my.crt"))
	assert.NilError(t, err)

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
