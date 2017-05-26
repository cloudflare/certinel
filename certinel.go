package certinel

import (
	"crypto/tls"
	"sync/atomic"
)

// Certinel is a container for zero-hit tls.Certificate changes, by
// receiving new certificates from sentries and presenting the functions
// expected by Go's tls.Config{}.
// Reading certificates from a Certinel instance is safe across multiple
// goroutines.
type Certinel struct {
	certificate atomic.Value // *tls.Certificate
	watcher     Watcher
	errBack     func(error)
}

// Watchers provide a way to construct (and close!) channels that
// bind a Certinel to a changing certificate.
type Watcher interface {
	Watch() (<-chan tls.Certificate, <-chan error)
	Close() error
}

// New creates a Certinel that watches for changes with the provided
// Watcher.
func New(w Watcher, errBack func(error)) *Certinel {
	if errBack == nil {
		errBack = func(error) {}
	}

	return &Certinel{
		watcher: w,
		errBack: errBack,
	}
}

// Watch setups the Certinel's channel handles and calls Watch on the
// held Watcher instance.
func (c *Certinel) Watch() {
	go func() {
		tlsChan, errChan := c.watcher.Watch()
		for {
			select {
			case certificate := <-tlsChan:
				c.certificate.Store(&certificate)
			case err := <-errChan:
				c.errBack(err)
			}
		}
	}()

	return
}

// Close calls Close on the held Watcher instance. After closing it
// is no longer safe to use this Certinel instance.
func (c *Certinel) Close() error {
	return c.watcher.Close()
}

// GetCertificate returns the current tls.Certificate instance. The function
// can be passed as the GetCertificate member in a tls.Config object. It is
// safe to call across multiple goroutines.
func (c *Certinel) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, _ := c.certificate.Load().(*tls.Certificate)
	return cert, nil
}
