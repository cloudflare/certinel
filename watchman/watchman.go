// Package watchman implements the Certinel interface by integrating with
// Facebook's Watchman file watching service.
package watchman

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sync/atomic"

	"github.com/sjansen/watchman"
)

// Sentinel is a client of Watchman which reloads the certificate when notified of changes.
type Sentinel struct {
	certPath, keyPath string
	certificate       atomic.Value
}

func New(cert, key string) (*Sentinel, error) {
	s := &Sentinel{
		certPath: cert,
		keyPath:  key,
	}

	if err := s.loadCertificate(); err != nil {
		return nil, fmt.Errorf("unable to load initial certificate: %w", err)
	}

	return s, nil
}

func (s *Sentinel) loadCertificate() error {
	certificate, err := tls.LoadX509KeyPair(s.certPath, s.keyPath)
	if err != nil {
		return fmt.Errorf("unable to load certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("unable to load certificate: %w", err)
	}

	certificate.Leaf = leaf

	s.certificate.Store(&certificate)
	return nil
}

func (s *Sentinel) Start(ctx context.Context) (err error) {
	c, err := watchman.Connect()
	if err != nil {
		return fmt.Errorf("unable to connect to Watchman service: %w", err)
	}
	defer c.Close()

	certPath := filepath.Clean(s.certPath)
	certDir, certFile := filepath.Split(certPath)
	certDir = certDir[:len(certDir)-1]
	realCertPath, err := filepath.EvalSymlinks(certPath)
	if err != nil {
		return fmt.Errorf("unable to resolve certificate symlink: %w", err)
	}

	w, err := c.AddWatch(certDir)
	if err != nil {
		return fmt.Errorf("unable to create watcher: %w", err)
	}

	sub, err := w.Subscribe("certinel", certDir)
	if err != nil {
		return fmt.Errorf("unable to create subscription: %w", err)
	}
	defer (func() {
		unSubErr := sub.Unsubscribe()
		switch {
		case err != nil:
			return
		case unSubErr != nil:
			err = unSubErr
			return
		}
	})()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case n := <-c.Notifications():
			cn, ok := n.(*watchman.ChangeNotification)
			if !ok || cn.IsFreshInstance {
				continue
			}

			currentPath, err := filepath.EvalSymlinks(certPath)
			if err != nil {
				return err
			}

			switch {
			case filesCreatedOrUpdated(certFile, cn.Files), symlinkModified(currentPath, realCertPath):
				realCertPath = currentPath

				if err := s.loadCertificate(); err != nil {
					return err
				}
			}
		}
	}
}

func (w *Sentinel) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, _ := w.certificate.Load().(*tls.Certificate)
	return cert, nil
}

func (w *Sentinel) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert, _ := w.certificate.Load().(*tls.Certificate)
	if cert == nil {
		cert = &tls.Certificate{}
	}

	return cert, nil
}

// filesCreatedOrUpdated predicate returns true when one of the files is the specified
// path and is created or updated.
func filesCreatedOrUpdated(path string, files []watchman.File) bool {
	for _, f := range files {
		if filepath.Clean(f.Name) == path && (f.Change == watchman.Created || f.Change == watchman.Updated) {
			return true
		}
	}

	return false
}

// symlinkModified predicate returns true when the current symlink path does
// not match the previous resolved path.
func symlinkModified(cur, prev string) bool {
	return cur != "" && cur != prev
}
