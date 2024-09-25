// Package fswatcher implements the Certinel interface by watching for filesystem
// change events using the cross-platform fsnotify package.
//
// This implementation watches the directory of the configured certificate to properly
// notice replacements and symlink updates, this allows fswatcher to be used within
// Kubernetes watching a certificate updated from a mounted ConfigMap or Secret.
package fswatcher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const ScopeName = "github.com/cloudflare/certinel/fswatcher"

// Sentinel watches for filesystem change events that effect the watched certificate.
type Sentinel struct {
	certPath, keyPath string
	certificate       atomic.Value
}

const fsCreateOrWriteOpMask = fsnotify.Create | fsnotify.Write

func New(cert, key string, opts ...Option) (*Sentinel, error) {
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

	fsw := &Sentinel{
		certPath: cert,
		keyPath:  key,
	}

	var err error
	_, err = meter.Int64ObservableGauge(
		"certificate.not_before_timestamp",
		metric.WithUnit("s"),
		metric.WithDescription("The time after which the certificate is valid. Expressed as seconds since the Unix Epoch"),
		metric.WithInt64Callback(fsw.observeNotBefore),
	)
	if err != nil {
		return nil, err
	}

	_, err = meter.Int64ObservableGauge(
		"certificate.not_after_timestamp",
		metric.WithUnit("s"),
		metric.WithDescription("The time after which the certificate is invalid. Expressed as seconds since the Unix Epoch"),
		metric.WithInt64Callback(fsw.observeNotAfter),
	)
	if err != nil {
		return nil, err
	}

	if err := fsw.loadCertificate(); err != nil {
		return nil, fmt.Errorf("unable to load initial certificate: %w", err)
	}

	return fsw, nil
}

func (w *Sentinel) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("unable to create watcher: %w", err)
	}
	defer watcher.Close()

	certPath := filepath.Clean(w.certPath)
	certDir, _ := filepath.Split(certPath)
	realCertPath, _ := filepath.EvalSymlinks(certPath)

	if err := watcher.Add(certDir); err != nil {
		return fmt.Errorf("unable to create watcher: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-watcher.Events:
			// Portions of this case are inspired by spf13/viper's WatchConfig.
			// (c) 2014 Steve Francia. MIT Licensed.
			currentPath, err := filepath.EvalSymlinks(certPath)
			if err != nil {
				return err
			}

			switch {
			case eventCreatesOrWritesPath(event, certPath), symlinkModified(currentPath, realCertPath):
				realCertPath = currentPath

				if err := w.loadCertificate(); err != nil {
					return err
				}
			}
		case err := <-watcher.Errors:
			return err
		}
	}
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

// eventCreatesOrWritesPath predicate returns true for fsnotify.Create and fsnotify.Write
// events that modify that specified path.
func eventCreatesOrWritesPath(event fsnotify.Event, path string) bool {
	return filepath.Clean(event.Name) == path && event.Op&fsCreateOrWriteOpMask != 0
}

// symlinkModified predicate returns true when the current symlink path does
// not match the previous resolved path.
func symlinkModified(cur, prev string) bool {
	return cur != "" && cur != prev
}
