// Package ticker implements the Certinel interface by polling the filesystem
// at a regular interval. This provides a reasonable alternative for environments
// not supported by the fsnotify package.
package ticker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// ticker allows swapping for a fake [time.Ticker] in tests.
type ticker interface {
	Chan() <-chan time.Time
	Stop()
}

// Sentinel polls the filesystem for changed certificates.
type Sentinel struct {
	certPath, keyPath string
	duration          time.Duration
	ticker            func(d time.Duration) ticker
	certificate       atomic.Pointer[tls.Certificate]
}

func New(cert, key string, duration time.Duration) (*Sentinel, error) {
	w := &Sentinel{
		certPath: cert,
		keyPath:  key,
		duration: duration,
		ticker:   newRealTicker,
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
	t := w.ticker(w.duration)
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
	return w.certificate.Load(), nil
}

func (w *Sentinel) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert := w.certificate.Load()
	if cert == nil {
		cert = &tls.Certificate{}
	}

	return cert, nil
}

type Vedette struct {
	caPath   string
	duration time.Duration
	ticker   func(d time.Duration) ticker
	pool     atomic.Pointer[x509.CertPool]
}

func NewVedette(ca string, duration time.Duration) (*Vedette, error) {
	w := &Vedette{
		caPath:   ca,
		duration: duration,
		ticker:   newRealTicker,
	}

	if err := w.loadCertificates(); err != nil {
		return nil, fmt.Errorf("unable to load initial certificate: %w", err)
	}

	return w, nil
}

func (w *Vedette) Start(ctx context.Context) error {
	t := w.ticker(w.duration)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.Chan():
			if err := w.loadCertificates(); err != nil {
				return err
			}
		}
	}
}

func (w *Vedette) loadCertificates() error {
	certs, err := os.ReadFile(w.caPath)
	if err != nil {
		return fmt.Errorf("unable to load certificates: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certs)
	w.pool.Store(pool)
	return nil
}

func (w *Vedette) GetCertPool() *x509.CertPool {
	return w.pool.Load()
}
