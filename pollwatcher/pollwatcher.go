package pollwatcher

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"time"

	"github.com/pkg/errors"
)

type Sentry struct {
	certPath     string
	keyPath      string
	pollInterval time.Duration
	stopChan     chan struct{}
	tlsChan      chan tls.Certificate
	errChan      chan error
}

const (
	errStatCertificate = "pollwatcher: error stat()'ing certificate"
	errLoadCertificate = "pollwatcher: error loading certificate"
)

func New(cert, key string, pollInterval time.Duration) *Sentry {
	fsw := &Sentry{
		certPath:     cert,
		keyPath:      key,
		pollInterval: pollInterval,
		stopChan:     make(chan struct{}),
		tlsChan:      make(chan tls.Certificate),
		errChan:      make(chan error),
	}
	return fsw
}

// Watch starts a goroutine that will check the certPath for changes every pollInterval and reload the keyPath and certPath when
// a change occurs.
func (w *Sentry) Watch() (<-chan tls.Certificate, <-chan error) {
	go func() {
		ticker := time.NewTicker(w.pollInterval)
		defer ticker.Stop()

		initialStat, err := os.Stat(w.certPath)
		if err != nil {
			w.errChan <- errors.Wrap(err, errStatCertificate)
			return
		}

		w.loadCertificate()

		for {
			select {
			case <-w.stopChan:
				return
			case <-ticker.C:
				stat, err := os.Stat(w.certPath)
				if err != nil {
					w.errChan <- errors.Wrap(err, errStatCertificate)
					return
				}
				if stat.Size() != initialStat.Size() || stat.ModTime() != initialStat.ModTime() {
					w.loadCertificate()
					initialStat = stat
				}
			}
		}
	}()

	return w.tlsChan, w.errChan
}

func (w *Sentry) Close() error {
	close(w.stopChan)
	close(w.tlsChan)
	close(w.errChan)
	return nil
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
