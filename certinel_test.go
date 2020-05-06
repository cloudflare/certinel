package certinel

import (
	"crypto/tls"
	"errors"
	"runtime"
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
	err := sentinel.Close()
	if err != nil {
		t.Error(err)
	}

	for i := 0; runtime.NumGoroutine() > goCount && i < 10; i++ {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}

	if n := runtime.NumGoroutine(); n > goCount {
		t.Errorf("expected %v goroutines, found %v", goCount, n)
	}
}
