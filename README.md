# certinel [![pkg.go.dev][godev-badge]][godev]

[godev-badge]: https://pkg.go.dev/badge/github.com/cloudflare/certinel.svg
[godev]: https://pkg.go.dev/github.com/cloudflare/certinel

Certinel is a Go library that makes it even easier to implement zero-hit
TLS certificate changes by watching for certificate changes for you. The
methods required by `tls.Config` are already implemented for you.

| Package                | Note                                                                           |
|------------------------|--------------------------------------------------------------------------------|
| [fswatcher][fswatcher] | Filesystem watcher for standard filesystems on Linux, BSD, macOS, and Windows. |
| [ticker][ticker]       | Filesystem watcher that polls at a defined interval.                           |

[fswatcher]: https://pkg.go.dev/github.com/cloudflare/certinel/fswatcher
[ticker]: https://pkg.go.dev/github.com/cloudflare/certinel/ticker

## Usage

Create the certinel instance, start it with `Start`, then pass the
`GetCertificate` method to your `tls.Config` instance.

```go
package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/cloudflare/certinel/fswatcher"
	"github.com/oklog/run"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	certinel, err := fswatcher.New("/etc/ssl/app.pem", "/etc/ssl/app.key")
	if err != nil {
		log.Fatalf("fatal: unable to read server certificate. err='%s'", err)
	}
	
	g := run.Group{}
	{
		g.Add(func() error {
			return certinel.Start(ctx)
		}, func(err error) {
			cancel()
		})
	}
	{
		ln, _ := tls.Listen("tcp", ":8000", &tls.Config{
			GetCertificate: certinel.GetCertificate,
		})
		g.Add(func() error {
			return http.Serve(ln, nil)
		}, func(err error) {
			ln.Close()
		})
	}
	
	if err := g.Run(); err != nil {
		log.Fatalf("err='%s'", err)
	}
}
```
