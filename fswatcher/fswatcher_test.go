package fswatcher_test

import (
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/certinel/fswatcher"
)

func TestClose(t *testing.T) {
	// Prepare (empty, invalid) cert and key files to watch.
	certFile, err := ioutil.TempFile("", "cert")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(certFile.Name())

	keyFile, err := ioutil.TempFile("", "key")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(keyFile.Name())

	// Record the number of goroutines before starting the watch.
	goCount := runtime.NumGoroutine()

	// Start a watcher and access its notification channels.
	watcher, err := fswatcher.New(certFile.Name(), keyFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	_, errChan := watcher.Watch()

	// Ensure an error is propagated from parsing the empty cert.
	select {
	case <-time.After(time.Second):
		t.Fatalf("expected a certificate error")
	case certErr, ok := <-errChan:
		if !ok || !strings.Contains(certErr.Error(), "failed to find any PEM data") {
			t.Error(certErr)
		}
	}

	// Close the watch and ensure all goroutines have exited.
	err = watcher.Close()
	if err != nil {
		t.Fatal(err)
	}

	if n := runtime.NumGoroutine(); n != goCount {
		t.Fatalf("expected %v goroutines, found %v", goCount, n)
	}

	// Ensure that the error channel has been closed.
	select {
	default:
		t.Errorf("default case on select of channel expected to be closed")
	case _, ok := <-errChan:
		if ok {
			t.Errorf("receive on channel expected to be closed")
		}
	}

	// Subsequent calls to Close return nil and do not panic.
	if err := watcher.Close(); err != nil {
		t.Error(err)
	}

	// Heavy cycling of fswatchers does not cause a race condition.
	for i := 0; i < 10; i++ {
		// Create a new watch.
		w, err := fswatcher.New(certFile.Name(), keyFile.Name())
		if err != nil {
			t.Fatal(err)
		}
		// Start the watch and drain channels.
		tlsCh, errCh := w.Watch()
		go func() {
			for range tlsCh {
			}
		}()
		go func() {
			for range errCh {
			}
		}()
		// Immediately close the watch, e.g. because a Dial failed.
		w.Close()

	}
}
