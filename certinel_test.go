package certinel

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockWatcher struct {
	mock.Mock
}

func (o *MockWatcher) Watch() (certCh <-chan tls.Certificate, errCh <-chan error) {
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
	cert := tls.Certificate{}
	clientHello := &tls.ClientHelloInfo{}
	watcher := &MockWatcher{}

	subject := &Certinel{
		watcher: watcher,
		errBack: func(error) {},
	}

	watcher.On("Watch").Return(tlsChan, errChan)
	watcher.On("Close").Return(nil).Run(func(args mock.Arguments) {
		close(tlsChan)
		close(errChan)
	})

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
	}
	cert2 := tls.Certificate{
		Certificate: [][]byte{
			[]byte("Goodbye"),
		},
	}
	clientHello := &tls.ClientHelloInfo{}
	watcher := &MockWatcher{}

	subject := &Certinel{
		watcher: watcher,
		errBack: func(error) {},
	}

	watcher.On("Watch").Return(tlsChan, errChan)
	watcher.On("Close").Return(nil).Run(func(args mock.Arguments) {
		close(tlsChan)
		close(errChan)
	})

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
	watcher.On("Close").Return(nil).Run(func(args mock.Arguments) {
		close(tlsChan)
		close(errChan)
	})

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
	watcher.On("Close").Return(nil).Run(func(args mock.Arguments) {
		close(tlsChan)
		close(errChan)
	})

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

func TestClose(t *testing.T) {
	// Set up a mock watcher and notification channels.
	tlsChan := make(chan tls.Certificate)
	errChan := make(chan error)
	watcher := &MockWatcher{}
	watcher.On("Watch").Return(tlsChan, errChan)
	watcher.On("Close").Return(nil).Run(func(args mock.Arguments) {
		close(tlsChan)
		close(errChan)
	})
	// Prepare the sentinel over the mock watcher.
	done := make(chan struct{})
	sentinel := &Certinel{
		watcher: watcher,
		errBack: func(err error) {
			if err == nil {
				t.Error("nil error provided to callback")
			} else {
				close(done)
			}
		},
	}

	// Record the number of goroutines before starting the watch.
	goCount := runtime.NumGoroutine()

	// Start the watch goroutine and test it propagates errors.
	sentinel.Watch()

	errChan <- errors.New("error")
	select {
	case <-time.After(time.Second):
		t.Errorf("never received error")
	case <-done:
	}

	// Close the sentinel and wait for the watch goroutine to exit.
	if err := sentinel.Close(); err != nil {
		t.Error(err)
	}

	if n := runtime.NumGoroutine(); n > goCount {
		t.Errorf("expected %v goroutines, found %v", goCount, n)
	}

	// Subsequent calls to Close return nil and do not panic.
	if err := sentinel.Close(); err != nil {
		t.Error(err)
	}
}

func TestGetClientCertificate(t *testing.T) {
	// Set up a TLS server that will ask for client certs.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}
	ts.StartTLS()

	defer ts.Close()

	// Set up a watcher that will never load any certifcates.
	tlsChan := make(chan tls.Certificate)
	errChan := make(chan error)
	watcher := &MockWatcher{}
	watcher.On("Watch").Return(tlsChan, errChan)
	watcher.On("Close").Return(nil).Run(func(args mock.Arguments) {
		close(tlsChan)
		close(errChan)
	})

	// Launch a Certinel and configure it to provide a client certificate.
	sentinel := New(watcher, nil)
	defer sentinel.Close()

	client := ts.Client()
	if transport, ok := client.Transport.(*http.Transport); !ok {
		t.Fatalf("Expected an *http.Transport: %T", client.Transport)
	} else {
		transport.TLSClientConfig.GetClientCertificate = sentinel.GetClientCertificate
	}

	// Attempt to perform a GET request.
	_, err := client.Get(ts.URL)
	if err == nil || !strings.Contains(err.Error(), "tls: bad certificate") {
		t.Fatalf("Expected TLS alert bad_certificate(42): error was %v", err)
	}
}
