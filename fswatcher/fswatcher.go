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

	if err != nil {
		return nil, errors.Wrap(err, errAddWatcher)
	}

	fsw := &Sentry{
		fsnotify: watcher,
		certPath: cert,
		keyPath:  key,
		tlsChan:  make(chan tls.Certificate),
		errChan:  make(chan error),
	}

	go func() {
		defer close(fsw.errChan)
		defer close(fsw.tlsChan)

		eventsCh, errorsCh := watcher.Events, watcher.Errors
		for eventsCh != nil && errorsCh != nil {
			select {
			case event, ok := <-eventsCh:
				if !ok {
					eventsCh = nil
				} else if event.Op&fsnotify.Write == fsnotify.Write {
					fsw.loadCertificate()
				}
			case err, ok := <-errorsCh:
				if !ok {
					errorsCh = nil
				} else {
					fsw.errChan <- err
				}
			}
		}
	}()

	return fsw, nil
}

func (w *Sentry) Watch() (certCh <-chan tls.Certificate, errCh <-chan error) {
	go func() {
		w.loadCertificate()
		err := w.fsnotify.Add(w.certPath)

		if err != nil {
			w.errChan <- err
		}
	}()

	return w.tlsChan, w.errChan
}

func (w *Sentry) Close() error {
	return w.fsnotify.Close()
}

func (w *Sentry) loadCertificate() {
	certificate, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		w.errChan <- errors.Wrap(err, errLoadCertificate)
		return
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		w.errChan <- errors.Wrap(err, errLoadCertificate)
		return
	}

	certificate.Leaf = leaf

	w.tlsChan <- certificate
}
