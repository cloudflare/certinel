package certinel

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/certinel/internal/fakewatcher"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestGetCertificate(t *testing.T) {
	watcher := fakewatcher.New()
	clientHello := &tls.ClientHelloInfo{}
	cert := tls.Certificate{
		Certificate: [][]byte{
			[]byte("Hello"),
		},
	}

	subject := New(watcher, nil)
	gotCert, err := subject.GetCertificate(clientHello)
	assert.NilError(t, err)
	assert.Assert(t, is.Nil(gotCert))

	subject.Watch()
	watcher.Observe(cert)

	err = subject.Wait(context.Background())
	assert.NilError(t, err)

	gotCert, err = subject.GetCertificate(clientHello)
	assert.NilError(t, err)
	assert.DeepEqual(t, gotCert, &cert)

	err = subject.Close()
	assert.NilError(t, err)
}

func TestWaitTimeout(t *testing.T) {
	watcher := fakewatcher.New()
	subject := New(watcher, nil)

	gotCert, err := subject.GetCertificate(&tls.ClientHelloInfo{})
	assert.NilError(t, err)
	assert.Assert(t, is.Nil(gotCert))

	subject.Watch()

	// We provide a context with a deadline in the past and don't send a cert
	// down the tls channel, so we expect Wait to return immediately with a
	// deadline exceeded error.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err = subject.Wait(ctx)
	assert.ErrorType(t, err, context.DeadlineExceeded)

	err = subject.Close()
	assert.NilError(t, err)
}

func TestGetCertificateAfterChange(t *testing.T) {
	watcher := fakewatcher.New()
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

	subject := New(watcher, nil)

	gotCert, err := subject.GetCertificate(clientHello)
	assert.NilError(t, err)
	assert.Assert(t, is.Nil(gotCert))

	subject.Watch()
	watcher.Observe(cert1)

	err = subject.Wait(context.Background())
	assert.NilError(t, err)

	gotCert, err = subject.GetCertificate(clientHello)
	assert.NilError(t, err)
	assert.DeepEqual(t, gotCert, &cert1)

	watcher.Observe(cert2)

	<-time.After(1 * time.Millisecond)

	gotCert, err = subject.GetCertificate(clientHello)
	assert.NilError(t, err)
	assert.DeepEqual(t, gotCert, &cert2)

	err = subject.Close()
	assert.NilError(t, err)
}

func BenchmarkGetCertificate(b *testing.B) {
	watcher := fakewatcher.New()
	cert := tls.Certificate{}
	clientHello := &tls.ClientHelloInfo{}

	subject := New(watcher, nil)

	subject.Watch()
	watcher.Observe(cert)

	for n := 0; n < b.N; n++ {
		subject.GetCertificate(clientHello) // nolint: errcheck
	}

	err := subject.Close()
	assert.NilError(b, err)
}

func BenchmarkGetCertificateParallel(b *testing.B) {
	watcher := fakewatcher.New()
	cert := tls.Certificate{}

	subject := New(watcher, nil)

	subject.Watch()
	watcher.Observe(cert)

	b.RunParallel(func(pb *testing.PB) {
		clientHello := &tls.ClientHelloInfo{}

		for pb.Next() {
			subject.GetCertificate(clientHello) // nolint: errcheck
		}
	})

	err := subject.Close()
	assert.NilError(b, err)
}

func TestClose(t *testing.T) {
	watcher := fakewatcher.New()

	// Prepare the sentinel over the mock watcher.
	done := make(chan struct{})
	errBack := func(err error) {
		if err == nil {
			t.Error("nil error provided to callback")
		} else {
			close(done)
		}
	}
	sentinel := New(watcher, errBack)

	// Start the watch goroutine and test it propagates errors.
	sentinel.Watch()

	watcher.Error(errors.New("error"))
	select {
	case <-time.After(time.Second):
		t.Errorf("never received error")
	case <-done:
	}

	// Close the sentinel and wait for the watch goroutine to exit.
	err := sentinel.Close()
	assert.NilError(t, err)

	// Subsequent calls to Close return nil and do not panic.
	err = sentinel.Close()
	assert.NilError(t, err)
}

func TestGetClientCertificate(t *testing.T) {
	// Set up a TLS server that will ask for client certs.
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS13,
	}
	ts.StartTLS()

	defer ts.Close()

	// Set up a watcher that will never load any certifcates.
	watcher := fakewatcher.New()

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
	assert.ErrorContains(t, err, "tls: bad certificate")
}
