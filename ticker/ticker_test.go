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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
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
	assert.ErrorIs(t, g.Wait(), context.Canceled)
}

func TestTickerMetrics(t *testing.T) {
	t.Parallel()

	reader := metric.NewManualReader()
	meter := metric.NewMeterProvider(metric.WithReader(reader))

	ctx, cancel := context.WithCancel(context.Background())
	clock := clockwork.NewFakeClock()

	pk := pkitest.NewPrivateKey(t)
	pemPK := pkitest.EncodePrivateKey(t, pk)

	dir := fs.NewDir(t, "test-ticker",
		fs.WithFile("my.key", "", fs.WithBytes(pemPK)),
		fs.WithFile("my.crt", "", fs.WithBytes(
			pkitest.PemEncodeCertificate(t, x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Date(2006, time.January, 2, 10, 4, 5, 0, time.UTC),
				NotAfter:     time.Date(2007, time.January, 2, 10, 4, 5, 0, time.UTC),
			}, pk),
		)),
	)
	defer dir.Remove()

	watcher, err := New(dir.Join("my.crt"), dir.Join("my.key"), 1*time.Minute, WithMeterProvider(meter))
	assert.NilError(t, err)

	watcher.clock = clock

	rm := metricdata.ResourceMetrics{}
	assert.NilError(t, reader.Collect(ctx, &rm))
	assert.Assert(t, len(rm.ScopeMetrics) == 1)

	assert.DeepEqual(t, instrumentation.Scope{
		Name:    "github.com/cloudflare/certinel/ticker",
		Version: "0.4.1",
	}, rm.ScopeMetrics[0].Scope)
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

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return watcher.Start(gctx)
	})

	fs.Apply(t, dir, fs.WithFile("my.crt", "", fs.WithBytes(
		pkitest.PemEncodeCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(2),
			NotBefore:    time.Date(2007, time.January, 2, 10, 4, 5, 0, time.UTC),
			NotAfter:     time.Date(2008, time.January, 2, 10, 4, 5, 0, time.UTC),
		}, pk),
	)))

	clock.BlockUntil(1)
	clock.Advance(1 * time.Minute)

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
