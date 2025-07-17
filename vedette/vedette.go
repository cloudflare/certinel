package verify

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/cloudflare/certinel"
)

func VerifyConnection(ca certinel.Vedette) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		opts := x509.VerifyOptions{
			DNSName:       cs.ServerName,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			Roots:         ca.GetCertPool(),
		}

		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
}
