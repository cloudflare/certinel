package fswatcher

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
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

const fsCreateOrWriteOpMask = fsnotify.Create | fsnotify.Write

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

		certPath := filepath.Clean(w.certPath)
		certDir, _ := filepath.Split(certPath)
		realCertPath, _ := filepath.EvalSymlinks(certPath)

		err := w.fsnotify.Add(certDir)

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
					// Portions of this case are inspired by spf13/viper's WatchConfig.
					// (c) 2014 Steve Francia. MIT Licensed.
					currentPath, err := filepath.EvalSymlinks(certPath)
					if err != nil {
						w.errChan <- err
					}

					switch {
					case !ok:
						eventsCh = nil
					case eventCreatesOrWritesPath(event, certPath), symlinkModified(currentPath, realCertPath):
						realCertPath = currentPath

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
