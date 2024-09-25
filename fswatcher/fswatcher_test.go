package fswatcher

import (
	"context"
	"crypto/x509"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/certinel/internel/pkitest"
	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
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
	assert.ErrorIs(t, g.Wait(), context.Canceled)
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
	assert.ErrorIs(t, g.Wait(), context.Canceled)
}

func TestWatcherMetrics(t *testing.T) {
	t.Parallel()

	reader := metric.NewManualReader()
	meter := metric.NewMeterProvider(metric.WithReader(reader))

	ctx, cancel := context.WithCancel(context.Background())

	pk := pkitest.NewPrivateKey(t)
	pemPK := pkitest.EncodePrivateKey(t, pk)

	dir := fs.NewDir(t, "test-symlink",
		fs.WithDir(".first", fs.WithFile("my.crt", "", fs.WithBytes(
			pkitest.PemEncodeCertificate(t, x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Date(2006, time.January, 2, 10, 4, 5, 0, time.UTC),
				NotAfter:     time.Date(2007, time.January, 2, 10, 4, 5, 0, time.UTC),
			}, pk),
		))),
		fs.WithDir(".second", fs.WithFile("my.crt", "", fs.WithBytes(
			pkitest.PemEncodeCertificate(t, x509.Certificate{
				SerialNumber: big.NewInt(2),
				NotBefore:    time.Date(2007, time.January, 2, 10, 4, 5, 0, time.UTC),
				NotAfter:     time.Date(2008, time.January, 2, 10, 4, 5, 0, time.UTC),
			}, pk),
		))),
		fs.WithFile("my.key", "", fs.WithBytes(pemPK)),
		fs.WithSymlink("my.crt", ".first/my.crt"),
	)
	defer dir.Remove()

	watcher, err := New(dir.Join("my.crt"), dir.Join("my.key"), WithMeterProvider(meter))
	assert.NilError(t, err)

	cert, err := watcher.GetCertificate(nil)
	assert.NilError(t, err)
	assert.DeepEqual(t, cert.Leaf.SerialNumber, big.NewInt(1), cmp.Comparer(pkitest.CmpBigInt))

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return watcher.Start(gctx)
	})
	<-time.After(100 * time.Millisecond)

	rm := metricdata.ResourceMetrics{}
	assert.NilError(t, reader.Collect(ctx, &rm))
	assert.Assert(t, len(rm.ScopeMetrics) == 1)

	wantedMetrics := []metricdata.Metrics{
		{
			Name: "certificate.not_before_timestamp",
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{
					{
						Attributes: attribute.NewSet(
							attribute.String("certificate.serial", "1"),
							attribute.String("certificate.path", dir.Join("my.crt")),
						),
						Value: 1136196245,
					},
				},
			},
			Description: "The time after which the certificate is valid. Expressed as seconds since the Unix Epoch",
			Unit:        "s",
		},
		{
			Name: "certificate.not_after_timestamp",
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{
					{
						Attributes: attribute.NewSet(
							attribute.String("certificate.serial", "1"),
							attribute.String("certificate.path", dir.Join("my.crt")),
						),
						Value: 1167732245,
					},
				},
			},
			Description: "The time after which the certificate is invalid. Expressed as seconds since the Unix Epoch",
			Unit:        "s",
		},
	}

	for i, want := range wantedMetrics {
		metricdatatest.AssertEqual(t, want, rm.ScopeMetrics[0].Metrics[i], metricdatatest.IgnoreTimestamp())
	}

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

	rm = metricdata.ResourceMetrics{}
	assert.NilError(t, reader.Collect(ctx, &rm))
	assert.Assert(t, len(rm.ScopeMetrics) == 1)

	wantedMetrics = []metricdata.Metrics{
		{
			Name: "certificate.not_before_timestamp",
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{
					{
						Attributes: attribute.NewSet(
							attribute.String("certificate.serial", "2"),
							attribute.String("certificate.path", dir.Join("my.crt")),
						),
						Value: 1167732245,
					},
				},
			},
			Description: "The time after which the certificate is valid. Expressed as seconds since the Unix Epoch",
			Unit:        "s",
		},
		{
			Name: "certificate.not_after_timestamp",
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{
					{
						Attributes: attribute.NewSet(
							attribute.String("certificate.serial", "2"),
							attribute.String("certificate.path", dir.Join("my.crt")),
						),
						Value: 1199268245,
					},
				},
			},
			Description: "The time after which the certificate is invalid. Expressed as seconds since the Unix Epoch",
			Unit:        "s",
		},
	}

	for i, want := range wantedMetrics {
		metricdatatest.AssertEqual(t, want, rm.ScopeMetrics[0].Metrics[i], metricdatatest.IgnoreTimestamp())
	}

	cancel()
	assert.ErrorIs(t, g.Wait(), context.Canceled)
}
