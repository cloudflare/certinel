# certinel [![GoDoc][godoc-badge]][godoc]

[godoc-badge]: https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square
[godoc]: https://godoc.org/github.com/cloudflare/certinel

Certinel is a Go library that makes it even easier to implement zero-hit
TLS certificate changes by watching for certificate changes for you. The
methods required by `tls.Config` are already implemented for you.

Right now there's support for listening to file system events on Linux,
BSDs, and Windows using the [fsnotify][fsnotify] library.

[fsnotify]: https://github.com/fsnotify/fsnotify

## Usage

Create the certinel instance, start it with `Watch`, then pass the
`GetCertificate` method to your `tls.Config` instance.

```go
package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/cloudflare/certinel"
	"github.com/cloudflare/certinel/fswatcher"
)

func main() {
	watcher, err := fswatcher.New("/etc/ssl/app.pem", "/etc/ssl/app.key")
	if err != nil {
		log.Fatalf("fatal: unable to read server certificate. err='%s'", err)
	}
	sentinel := certinel.New(watcher, func(err error) {
		log.Printf("error: certinel was unable to reload the certificate. err='%s'", err)
	})

	sentinel.Watch()

	// Optional: block until the initial certificate load completes.
	if err := sentinel.Wait(context.Background()); err != nil {
		log.Fatalf("fatal: unable to read server certificate. err='%s'", err)
	}

	server := http.Server{
		Addr: ":8000",
		TLSConfig: &tls.Config{
			GetCertificate: sentinel.GetCertificate,
		},
	}
	
	server.ListenAndServeTLS("", "")
}
```
