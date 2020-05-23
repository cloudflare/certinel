package fswatcher

import (
	"crypto/tls"
	"crypto/x509"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
)

type Sentry struct {
	fsnotify *fsnotify.Watcher
	certPath string
	keyPath  string
	tlsChan  chan tls.Certificate
	errChan  chan error

	watchOnce sync.Once
	closeOnce sync.Once
	done      chan struct{}
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
		done:     make(chan struct{}),
	}
	return fsw, nil
}

func (w *Sentry) Watch() (certCh <-chan tls.Certificate, errCh <-chan error) {
	w.watchOnce.Do(func() {
		w.tlsChan = make(chan tls.Certificate)
		w.errChan = make(chan error)

		err := w.fsnotify.Add(w.certPath)

		go func() {
			defer close(w.done)
			defer close(w.errChan)
			defer close(w.tlsChan)

			if err != nil {
				w.errChan <- err
			}
			w.loadCertificate()

			eventsCh, errorsCh := w.fsnotify.Events, w.fsnotify.Errors
			for eventsCh != nil && errorsCh != nil {
				select {
				case event, ok := <-eventsCh:
					if !ok {
						eventsCh = nil
					} else if event.Op&fsnotify.Write == fsnotify.Write {
						w.loadCertificate()
					}
				case err, ok := <-errorsCh:
					if !ok {
						errorsCh = nil
					} else {
						w.errChan <- err
					}
				}
			}
		}()
	})

	return w.tlsChan, w.errChan
}

func (w *Sentry) Close() (err error) {
	w.closeOnce.Do(func() {
		err = w.fsnotify.Close()
	})

	<-w.done

	return err
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
