package certinel

import (
	"crypto/tls"
	"sync"
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
	watchOnce   sync.Once
	closeOnce   sync.Once
	done        chan struct{}
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
	c.watchOnce.Do(func() {
		c.done = make(chan struct{})
		go func() {
			defer close(c.done)
			tlsChan, errChan := c.watcher.Watch()

			for tlsChan != nil && errChan != nil {
				select {
				case certificate, ok := <-tlsChan:
					if ok {
						c.certificate.Store(&certificate)
					} else {
						tlsChan = nil
					}
				case err, ok := <-errChan:
					if ok {
						c.errBack(err)
					} else {
						errChan = nil
					}
				}
			}
		}()
	})
}

// Close calls Close on the held Watcher instance. After closing it
// is no longer safe to use this Certinel instance.
func (c *Certinel) Close() (err error) {
	// Prevent Watch after Close, since it launches the watcher routine.
	c.watchOnce.Do(func() {})

	c.closeOnce.Do(func() {
		err = c.watcher.Close()
	})

	if c.done != nil {
		<-c.done
	}

	return err
}

// GetCertificate returns the current tls.Certificate instance. The function
// can be passed as the GetCertificate member in a tls.Config object. It is
// safe to call across multiple goroutines.
func (c *Certinel) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, _ := c.certificate.Load().(*tls.Certificate)
	return cert, nil
}

// GetClientCertificate returns the current tls.Certificate instance. The function
// can be passed as the GetClientCertificate member in a tls.Config object. It is
// safe to call across multiple goroutines.
func (c *Certinel) GetClientCertificate(certificateRequest *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert, _ := c.certificate.Load().(*tls.Certificate)
	if cert == nil {
		return &tls.Certificate{}, nil
	} else {
		return cert, nil
	}
}
