package certinel

import (
	"crypto/tls"
	"sync"
)

// Certinel is a container for zero-hit tls.Certificate changes, by
// receiving new certificates from sentries and presenting the functions
// expected by Go's tls.Config{}.
// Reading certificates from a Certinel instance is safe across multiple
// goroutines.
type Certinel struct {
	mu          sync.RWMutex
	certificate *tls.Certificate
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
				c.loadCertificate(certificate)
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
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.certificate, nil
}

func (c *Certinel) loadCertificate(certificate tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.certificate = &certificate
}
