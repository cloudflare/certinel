// Package certinel defines the Certinel and Runnable interfaces for watching
// for implementing zero-hit rotations of TLS certificates.
package certinel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
)

// A Certinel implementation watches certificates for changes, and returns the
// desired certificate when requested by Go's crypto/tls implementation.
type Certinel interface {
	GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// A Vedette implementation watches for changes to a Certificate Authority, and
// returns a [*x509.CertPool] to validate against. Can be paired with
// [github.com/cloudflare/certinel/vedette.VerifyConnection] to be utilized with a
// [tls.Config].
type Vedette interface {
	GetCertPool() *x509.CertPool
}

// Runnable is implemented by Certinel instances that perform asynchronous actions.
type Runnable interface {
	// Start starts running the asynchronous actions that make up the Certinel
	// instances. The instance will stop running when the context is closed.
	// Start blocks until the context is closed or an error occures.
	Start(ctx context.Context) error
}
