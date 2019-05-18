package certinel

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockWatcher struct {
	mock.Mock
}

func (o *MockWatcher) Watch() (<-chan tls.Certificate, <-chan error) {
	args := o.Called()

	return args.Get(0).(chan tls.Certificate), args.Get(1).(chan error)
}

func (o *MockWatcher) Close() error {
	args := o.Called()

	return args.Error(0)
}

func TestGetCertificate(t *testing.T) {
	tlsChan := make(chan tls.Certificate)
	errChan := make(chan error)
	cert := tls.Certificate{
		Certificate: [][]byte{
			[]byte("Hello"),
		},
		Leaf: &x509.Certificate{
			Subject:   pkix.Name{CommonName: "foo"},
			NotBefore: time.Now(),
			NotAfter:  time.Now(),
		},
	}
	clientHello := &tls.ClientHelloInfo{}
	watcher := &MockWatcher{}

	subject := &Certinel{
		watcher: watcher,
		errBack: func(error) {},
		log:     nullLogger{},
	}

	watcher.On("Watch").Return(tlsChan, errChan)
	watcher.On("Close").Return(nil)

	gotCert, err := subject.GetCertificate(clientHello)
	if assert.NoError(t, err) {
		assert.Nil(t, gotCert)
	}

	subject.Watch()
	tlsChan <- cert
	<-time.After(time.Duration(1) * time.Millisecond)

	gotCert, err = subject.GetCertificate(clientHello)
	if assert.NoError(t, err) {
		assert.Equal(t, cert, *gotCert)
	}

	subject.Close() // nolint: errcheck

	watcher.AssertExpectations(t)
}

func TestGetCertificateAfterChange(t *testing.T) {
	tlsChan := make(chan tls.Certificate)
	errChan := make(chan error)
	cert1 := tls.Certificate{
		Certificate: [][]byte{
			[]byte("Hello"),
		},
		Leaf: &x509.Certificate{
			Subject:   pkix.Name{CommonName: "cert1"},
			NotBefore: time.Now(),
			NotAfter:  time.Now(),
		},
	}
	cert2 := tls.Certificate{
		Certificate: [][]byte{
			[]byte("Goodbye"),
		},
		Leaf: &x509.Certificate{
			Subject:   pkix.Name{CommonName: "cert2"},
			NotBefore: time.Now(),
			NotAfter:  time.Now(),
		},
	}
	clientHello := &tls.ClientHelloInfo{}
	watcher := &MockWatcher{}

	subject := &Certinel{
		watcher: watcher,
		errBack: func(error) {},
		log:     nullLogger{},
	}

	watcher.On("Watch").Return(tlsChan, errChan)
	watcher.On("Close").Return(nil)

	gotCert, err := subject.GetCertificate(clientHello)
	if assert.NoError(t, err) {
		assert.Nil(t, gotCert)
	}

	subject.Watch()
	tlsChan <- cert1
	<-time.After(time.Duration(1) * time.Millisecond)

	gotCert, err = subject.GetCertificate(clientHello)
	if assert.NoError(t, err) {
		assert.Equal(t, cert1, *gotCert)
	}

	tlsChan <- cert2
	<-time.After(time.Duration(1) * time.Millisecond)
	gotCert, err = subject.GetCertificate(clientHello)
	if assert.NoError(t, err) {
		assert.Equal(t, cert2, *gotCert)
	}

	subject.Close() // nolint: errcheck

	watcher.AssertExpectations(t)
}

func BenchmarkGetCertificate(b *testing.B) {
	tlsChan := make(chan tls.Certificate)
	errChan := make(chan error)
	cert := tls.Certificate{}
	clientHello := &tls.ClientHelloInfo{}
	watcher := &MockWatcher{}

	subject := &Certinel{
		watcher: watcher,
		errBack: func(error) {},
	}

	watcher.On("Watch").Return(tlsChan, errChan)
	watcher.On("Close").Return(nil)

	subject.Watch()
	tlsChan <- cert

	for n := 0; n < b.N; n++ {
		subject.GetCertificate(clientHello) // nolint: errcheck
	}

	subject.Close() // nolint: errcheck

	watcher.AssertExpectations(b)
}

func BenchmarkGetCertificateParallel(b *testing.B) {
	tlsChan := make(chan tls.Certificate)
	errChan := make(chan error)
	cert := tls.Certificate{}
	watcher := &MockWatcher{}

	subject := &Certinel{
		watcher: watcher,
		errBack: func(error) {},
	}

	watcher.On("Watch").Return(tlsChan, errChan)
	watcher.On("Close").Return(nil)

	subject.Watch()
	tlsChan <- cert

	b.RunParallel(func(pb *testing.PB) {
		clientHello := &tls.ClientHelloInfo{}

		for pb.Next() {
			subject.GetCertificate(clientHello) // nolint: errcheck
		}
	})

	subject.Close() // nolint: errcheck

	watcher.AssertExpectations(b)
}
