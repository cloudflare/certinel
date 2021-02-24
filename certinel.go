package certinel

import (
	"crypto/tls"
	"sync/atomic"
)

type logger interface {
	Printf(string, ...interface{})
}

type nullLogger struct{}

func (l nullLogger) Printf(string, ...interface{}) {}

// Certinel is a container for zero-hit tls.Certificate changes, by
// receiving new certificates from sentries and presenting the functions
// expected by Go's tls.Config{}.
// Reading certificates from a Certinel instance is safe across multiple
// goroutines.
type Certinel struct {
	certificate atomic.Value // *tls.Certificate
	watcher     Watcher
	errBack     func(error)
	log         logger
}

// Watchers provide a way to construct (and close!) channels that
// bind a Certinel to a changing certificate.
type Watcher interface {
	Watch() (<-chan tls.Certificate, <-chan error)
	Close() error
}

// New creates a Certinel that watches for changes with the provided
// Watcher. Takes an optional logger and errBack func. Both can be nil if you don't want to log
// or handle errors.
func New(w Watcher, log logger, errBack func(error)) *Certinel {
	if errBack == nil {
		errBack = func(error) {}
	}

	if log == nil {
		log = nullLogger{}
	}

	return &Certinel{
		watcher: w,
		log:     log,
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
				c.log.Printf("Loading new certificate: Subject: '%s', NotBefore: '%s', NotAfter: '%s'",
					certificate.Leaf.Subject, certificate.Leaf.NotBefore, certificate.Leaf.NotAfter)
				c.certificate.Store(&certificate)
			case err := <-errChan:
				c.errBack(err)
			}
		}
	}()
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

// GetClientCertificate returns the current tls.Certificate instance. The function
// can be passed as the GetClientCertificate member in a tls.Config object. (Introduced in go-1.8)
// It is safe to call across multiple goroutines.
func (c *Certinel) GetClientCertificate(certificateRequest *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert, _ := c.certificate.Load().(*tls.Certificate)
	return cert, nil
}
