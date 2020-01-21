package fswatcher

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("missing cert files", func(t *testing.T) {
		sentry, err := New("./testdata/missing_cert.pem", "./testdata/key.pem")
		require.EqualError(t, err, "fswatcher: error adding path to watcher: lstat testdata/missing_cert.pem: no such file or directory")
		require.Nil(t, sentry)
	})
	t.Run("garbage cert files", func(t *testing.T) {
		sentry, err := New("./testdata/garbage.pem", "./testdata/key.pem")
		require.EqualError(t, err, "fswatcher: error loading certificate: tls: failed to find any PEM data in certificate input")
		require.Nil(t, sentry)
	})
	t.Run("ok", func(t *testing.T) {
		sentry, err := New("./testdata/cert.pem", "./testdata/key.pem")
		require.NoError(t, err)
		select {
		case <-sentry.tlsChan:
			// there is a cert already loaded
		default:
			t.Error("Expecting a certificate to be already loaded")
		}
	})
}
