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

	// out channels are the channels returned by Watch
	// and represent part of the public API. They are expected
	// to be closed by clients.
	outTLSCh chan tls.Certificate
	outErrCh chan error

	// int channels coordinate multiple senders to the
	// out channels. They are not closed.
	intTLSCh chan tls.Certificate
	intErrCh chan error

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
		fsnotify:  watcher,
		certPath:  cert,
		keyPath:   key,
		outTLSCh:  make(chan tls.Certificate),
		outErrCh:  make(chan error),
		intTLSCh:  make(chan tls.Certificate),
		intErrCh:  make(chan error),
		closingCh: make(chan struct{}),
		closedCh:  make(chan struct{}),
	}

	go fsw.runCoordination()
	go fsw.runNotifyHandler(watcher)

	return fsw, nil
}

func (w *Sentry) Watch() (certCh <-chan tls.Certificate, errCh <-chan error) {
	go func() {
		w.loadCertificate()
		err := w.fsnotify.Add(w.certPath)

		if err != nil {
			select {
			case <-w.closedCh:
				return
			default:
			}

			select {
			case <-w.closedCh:
				return
			case w.intErrCh <- err:
			}
		}
	}()

	return w.outTLSCh, w.outErrCh
}

func (w *Sentry) Close() error {
	select {
	case <-w.closedCh:
		return nil
	default:
	}

	err := w.fsnotify.Close()
	w.stop()

	return err
}

func (w *Sentry) loadCertificate() {
	certificate, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		err = errors.Wrap(err, errLoadCertificate)
		select {
		case <-w.closedCh:
			return
		default:
		}

		select {
		case <-w.closedCh:
			return
		case w.intErrCh <- err:
		}

		return
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		err = errors.Wrap(err, errLoadCertificate)
		select {
		case <-w.closedCh:
			return
		default:
		}

		select {
		case <-w.closedCh:
			return
		case w.outErrCh <- err:
		}

		return
	}

	certificate.Leaf = leaf

	w.outTLSCh <- certificate
}

func (w *Sentry) runCoordination() {
	stop := func() {
		close(w.closedCh)
		close(w.outTLSCh)
		close(w.outErrCh)
	}

	for {
		select {
		case <-w.closingCh:
			stop()
			return
		case cert := <-w.intTLSCh:
			select {
			case <-w.closingCh:
				stop()
				return
			case w.outTLSCh <- cert:
			}
		case err := <-w.intErrCh:
			select {
			case <-w.closingCh:
				stop()
				return
			case w.outErrCh <- err:
			}
		}
	}
}

func (w *Sentry) runNotifyHandler(watcher *fsnotify.Watcher) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Write == fsnotify.Write {
				w.loadCertificate()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}

			select {
			case <-w.closedCh:
				return
			default:
			}

			select {
			case <-w.closedCh:
				return
			case w.intErrCh <- err:
			}
		}
	}
}

func (w *Sentry) stop() {
	select {
	case w.closingCh <- struct{}{}:
		<-w.closedCh
	case <-w.closedCh:
	}
}
