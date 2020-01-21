package fswatcher

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
)

type Sentry struct {
	fsnotify *fsnotify.Watcher
	certPath string
	keyPath  string
	tlsChan  chan tls.Certificate
	errChan  chan error
}

const (
	errAddWatcher      = "fswatcher: error adding path to watcher"
	errCreateWatcher   = "fswatcher: error creating watcher"
	errLoadCertificate = "fswatcher: error loading certificate"
)

// New creates a Sentry to watch for file system changes.
func New(cert, key string) (*Sentry, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, errors.Wrap(err, errCreateWatcher)
	}

	if err = watcher.Add(cert); err != nil {
		return nil, errors.Wrap(err, errAddWatcher)
	}

	fsw := &Sentry{
		fsnotify: watcher,
		certPath: cert,
		keyPath:  key,
		tlsChan:  make(chan tls.Certificate, 1),
		errChan:  make(chan error),
	}

	tls, err := fsw.loadCertificate()
	if err != nil {
		return nil, err
	}
	fsw.tlsChan <- tls

	return fsw, nil
}

func (w *Sentry) Watch() (<-chan tls.Certificate, <-chan error) {
	go func() {
		for {
			select {
			case event := <-w.fsnotify.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					cert, err := w.loadCertificate()
					if err != nil {
						w.errChan <- err
					} else {
						w.tlsChan <- cert
					}
				}
			case err := <-w.fsnotify.Errors:
				w.errChan <- err
			}
		}
	}()

	return w.tlsChan, w.errChan
}

func (w *Sentry) Close() error {
	err := w.fsnotify.Close()

	close(w.tlsChan)
	close(w.errChan)
	return err
}

func (w *Sentry) loadCertificate() (tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, errLoadCertificate)
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, errLoadCertificate)
	}

	certificate.Leaf = leaf

	return certificate, nil
}
