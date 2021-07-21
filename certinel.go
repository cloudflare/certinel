// Package certinel defines the Certinel and Runnable interfaces for watching
// for implementing zero-hit rotations of TLS certificates.
package certinel

import (
	"context"
	"crypto/tls"
)

// A Certinel implementation watches certificates for changes, and returns the
// desired certificate when requested by Go's crypto/tls implementation.
type Certinel interface {
	GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// Runnable is implemented by Certinel instances that perform asynchronous actions.
type Runnable interface {
	// Start starts running the asynchronous actions that make up the Certinel
	// instances. The instance will stop running when the context is closed.
	// Start blocks until the context is closed or an error occures.
	Start(ctx context.Context) error
}
