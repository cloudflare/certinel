package fswatcher

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
)

type Sentry struct {
	fsnotify *fsnotify.Watcher
	certPath string
	keyPath  string

	// out channels are the channels returned by Watch
	// and represent part of the public API. They will be
	// closed after a call to Close.
	Certificates chan tls.Certificate
	Errors       chan error

	// certCh coordinates multiple senders to the out channels.
	// It is closed after all senders are stopped.
	certCh chan certOrErr

	// loadCertCh triggers a load of the cert from disk.
	loadCertCh chan struct{}

	// closingCh signals to the coordination goroutine
	// that the out channels should be closed.
	closingCh chan struct{}

	// closedch signals that out channels are closed.
	closedCh chan struct{}
}

const (
	errAddWatcher      = "fswatcher: error adding path to watcher"
	errCreateWatcher   = "fswatcher: error creating watcher"
	errLoadCertificate = "fswatcher: error loading certificate"
)

type certOrErr struct {
	cert tls.Certificate
	err  error
}

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
		fsnotify:     watcher,
		certPath:     cert,
		keyPath:      key,
		Certificates: make(chan tls.Certificate),
		Errors:       make(chan error),
		certCh:       make(chan certOrErr),
		loadCertCh:   make(chan struct{}, 1),
		closingCh:    make(chan struct{}),
		closedCh:     make(chan struct{}, 2), // 1 for each helper goroutine we spawn
	}

	// Trigger the initial load. Buffered so it doesn't block.
	fsw.loadCertCh <- struct{}{}

	go fsw.runCoordination()
	go fsw.runNotifyHandler(watcher)

	return fsw, nil
}

func (w *Sentry) Watch() error {
	log.Printf("Sentry.Watch")
	return w.fsnotify.Add(w.certPath)
}

func (w *Sentry) Close() error {
	log.Printf("Sentry.Close")
	if err := w.fsnotify.Close(); err != nil {
		return err
	}
	close(w.closingCh)
	for i := 0; i < 2; i++ {
		<-w.closedCh
	}
	close(w.closedCh)
	return nil
}

func (w *Sentry) loadCertificate() (tls.Certificate, error) {
	log.Printf("Sentry.loadCertificate")

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

func (w *Sentry) runCoordination() {
	log.Printf("Sentry.runCoordination")

	for paylaod := range w.certCh {
		if paylaod.err != nil {
			select {
			case <-w.closingCh:
				break
			case w.Errors <- paylaod.err:
			}
		} else {
			select {
			case <-w.closingCh:
				break
			case w.Certificates <- paylaod.cert:
			}
		}
	}
	log.Printf("certCh closed")

	close(w.Certificates)
	close(w.Errors)

	// Signal that we're done.
	log.Printf("Sentry.runCoordination waiting on closedCh")
	w.closedCh <- struct{}{}

	log.Printf("Sentry.runCoordination returning")
}

func (w *Sentry) runNotifyHandler(watcher *fsnotify.Watcher) {
	log.Printf("Sentry.runNotifyHandler")

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		for range w.loadCertCh {
			cert, err := w.loadCertificate()
			select {
			case <-w.closingCh:
				break
			case w.certCh <- certOrErr{cert: cert, err: err}:
			}
		}
		log.Printf("loadCertCh closed")
		wg.Done()
	}()

	go func() {
		for event := range watcher.Events {
			if event.Op&fsnotify.Write == fsnotify.Write {
				select {
				case <-w.closingCh:
					break
				case w.loadCertCh <- struct{}{}:
				}
			}
		}
		log.Printf("watcher.Events closed")

		// Close the loader channel to signal the goroutine above us to exit;
		// safe to do since we're the only writer to the channel once spawned.
		close(w.loadCertCh)

		wg.Done()
	}()

	go func() {
		for err := range watcher.Errors {
			select {
			case <-w.closingCh:
				break
			case w.certCh <- certOrErr{err: err}:
			}
		}
		log.Printf("watcher.Errors closed")
		wg.Done()
	}()

	log.Printf("Sentry.runNotifyHandler waiting on WaitGroup")
	wg.Wait()

	close(w.certCh)

	// Signal that we're done.
	log.Printf("Sentry.runNotifyHandler waiting on closedCh")
	w.closedCh <- struct{}{}

	log.Printf("Sentry.runNotifyHandler returning")
}
