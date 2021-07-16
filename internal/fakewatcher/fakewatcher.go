package fakewatcher

import (
	"crypto/tls"
	"sync"
)

type FakeWatcher struct {
	certCh chan tls.Certificate
	errCh  chan error

	mu     sync.Mutex
	closed bool
}

func New() *FakeWatcher {
	return &FakeWatcher{
		certCh: make(chan tls.Certificate),
		errCh:  make(chan error),
	}
}

func (w *FakeWatcher) Watch() (certCh <-chan tls.Certificate, errCh <-chan error) {
	return w.certCh, w.errCh
}

func (w *FakeWatcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	close(w.certCh)
	close(w.errCh)
	w.closed = true

	return nil
}

func (w *FakeWatcher) Observe(cert tls.Certificate) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.closed {
		w.certCh <- cert
	}
}

func (w *FakeWatcher) Error(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.closed {
		w.errCh <- err
	}
}
