// +build go1.8

package certinel

import (
	"crypto/tls"
)

// GetClientCertificate returns the current tls.Certificate instance. The function
// can be passed as the GetClientCertificate member in a tls.Config object. It is
// safe to call across multiple goroutines.
func (c *Certinel) GetClientCertificate(certificateRequest *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.certificate, nil
}
