// Package ticker implements the Certinel interface by polling the filesystem
// at a regular interval. This provides a reasonable alternative for environments
// not supported by the fsnotify package.
package ticker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jonboulle/clockwork"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const ScopeName = "github.com/cloudflare/certinel/ticker"

// Sentinel polls the filesystem for changed certificates.
type Sentinel struct {
	certPath, keyPath string
	duration          time.Duration
	clock             clockwork.Clock
	certificate       atomic.Value
}

func New(cert, key string, duration time.Duration, opts ...Option) (*Sentinel, error) {
	cfg := &config{
		MeterProvider: otel.GetMeterProvider(),
	}

	for _, opt := range opts {
		opt.apply(cfg)
	}

	meter := cfg.MeterProvider.Meter(
		ScopeName,
		metric.WithInstrumentationVersion("0.4.1"),
	)

	w := &Sentinel{
		certPath: cert,
		keyPath:  key,
		duration: duration,
		clock:    clockwork.NewRealClock(),
	}

	var err error
	_, err = meter.Int64ObservableGauge(
		"certificate.not_before_timestamp",
		metric.WithUnit("s"),
		metric.WithDescription("The time after which the certificate is valid. Expressed as seconds since the Unix Epoch"),
		metric.WithInt64Callback(w.observeNotBefore),
	)
	if err != nil {
		return nil, err
	}

	_, err = meter.Int64ObservableGauge(
		"certificate.not_after_timestamp",
		metric.WithUnit("s"),
		metric.WithDescription("The time after which the certificate is invalid. Expressed as seconds since the Unix Epoch"),
		metric.WithInt64Callback(w.observeNotAfter),
	)
	if err != nil {
		return nil, err
	}

	if err := w.loadCertificate(); err != nil {
		return nil, fmt.Errorf("unable to load initial certificate: %w", err)
	}

	return w, nil
}

func (w *Sentinel) loadCertificate() error {
	certificate, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		return fmt.Errorf("unable to load certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("unable to load certificate: %w", err)
	}

	certificate.Leaf = leaf

	w.certificate.Store(&certificate)
	return nil
}

func (w *Sentinel) Start(ctx context.Context) error {
	t := w.clock.NewTicker(w.duration)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.Chan():
			if err := w.loadCertificate(); err != nil {
				return err
			}
		}
	}
}

func (w *Sentinel) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, _ := w.certificate.Load().(*tls.Certificate)
	return cert, nil
}

func (w *Sentinel) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert, _ := w.certificate.Load().(*tls.Certificate)
	if cert == nil {
		cert = &tls.Certificate{}
	}

	return cert, nil
}

func (w *Sentinel) observeNotBefore(_ context.Context, io metric.Int64Observer) error {
	cert, _ := w.certificate.Load().(*tls.Certificate)
	if cert != nil {
		io.Observe(
			cert.Leaf.NotBefore.Unix(),
			metric.WithAttributes(
				attribute.String("certificate.serial", cert.Leaf.SerialNumber.String()),
				attribute.String("certificate.path", w.certPath),
			),
		)
	}
	return nil
}

func (w *Sentinel) observeNotAfter(_ context.Context, io metric.Int64Observer) error {
	cert, _ := w.certificate.Load().(*tls.Certificate)
	if cert != nil {
		io.Observe(
			cert.Leaf.NotAfter.Unix(),
			metric.WithAttributes(
				attribute.String("certificate.serial", cert.Leaf.SerialNumber.String()),
				attribute.String("certificate.path", w.certPath),
			),
		)
	}
	return nil
}
