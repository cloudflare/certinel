//go:build !windows
// +build !windows

package watchman

import (
	"context"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
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

const (
	atomicDirName    = "..data"
	atomicNewDirName = "..data_tmp"
)

func TestWatcher_AtomicWriter(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	pk1 := pkitest.NewPrivateKey(t)
	pemPK1 := pkitest.EncodePrivateKey(t, pk1)

	pk2 := pkitest.NewPrivateKey(t)
	pemPK2 := pkitest.EncodePrivateKey(t, pk2)

	dir := fs.NewDir(t, "test-symlink",
		fs.WithDir(".first",
			fs.WithFile("my.crt", "", fs.WithBytes(
				pkitest.PemEncodeCertificate(t, x509.Certificate{
					SerialNumber: big.NewInt(1),
				}, pk1),
			)),
			fs.WithFile("my.key", "", fs.WithBytes(pemPK1)),
		),
		fs.WithDir(".second",
			fs.WithFile("my.crt", "", fs.WithBytes(
				pkitest.PemEncodeCertificate(t, x509.Certificate{
					SerialNumber: big.NewInt(2),
				}, pk2),
			)),
			fs.WithFile("my.key", "", fs.WithBytes(pemPK2)),
		),
		fs.WithSymlink(atomicDirName, ".first"),
		fs.WithSymlink("my.key", filepath.Join(atomicDirName, "my.key")),
		fs.WithSymlink("my.crt", filepath.Join(atomicDirName, "my.crt")),
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

	fs.Apply(t, dir, fs.WithSymlink(atomicNewDirName, ".second"))

	err = os.Rename(dir.Join(atomicNewDirName), dir.Join(atomicDirName))
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
