package certinel

import (
	"crypto/tls"
	"fmt"
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
	tlsChan     <-chan tls.Certificate
	errChan     <-chan error
	closed      bool
	done        chan struct{}
	lock        sync.Mutex
}

// Watcher provides a way to construct (and close!) channels that
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

// Watch sets up the Certinel's channel handles and calls Watch on the held
// Watcher instance. It blocks until the initial load of the key pair. Once it
// returns with a nil error, GetCertificate and GetClientCertificate are ready
// for use.
func (c *Certinel) Watch() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.done != nil || c.closed {
		return nil
	}

	c.done = make(chan struct{})
	c.tlsChan, c.errChan = c.watcher.Watch()

	// Block until we load the key pair for this first time. This allows clients
	// to fail fast in case of error, and otherwise know subsequent calls to
	// GetCertificate/GetClientCertificate will succeed.
	ok, err := c.processEvent()
	if !ok {
		return fmt.Errorf("closed")
	} else if err != nil {
		return err
	}

	go func() {
		defer close(c.done)
		for {
			ok, err := c.processEvent()
			if !ok {
				return
			}
			if err != nil {
				c.errBack(err)
			}
		}
	}()

	return nil
}

func (c *Certinel) processEvent() (bool, error) {
	select {
	case certificate, ok := <-c.tlsChan:
		if !ok {
			return false, nil
		}
		c.certificate.Store(&certificate)
		return true, nil
	case err, ok := <-c.errChan:
		if !ok {
			return false, nil
		}
		return true, err
	}
}

// Close calls Close on the held Watcher instance. After closing it
// is no longer safe to use this Certinel instance.
func (c *Certinel) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.done == nil || c.closed {
		return nil
	}

	c.closed = true

	// Close the watcher. This will in turn close its channels, which will
	// signal the event loop goroutine to exit.
	err := c.watcher.Close()

	// Now wait for the event loop goroutine to exit.
	<-c.done

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
