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

### Use Atomic Update Pattern

If using a filesystem-based certinel with in an environment where both
the keys and certificates are updated, care should be taken to update
both atomically. This is automatically done in some environments, such
as mounting a secret as a volume in Kubernetes.

1. Create the initial key and certificate in a hidden directory.
   (`./ssl/.first/app.pem` and `./ssl/.first/app.key`)
2. Create hidden symlink to this directory (`./ssl/..data` ->
   `./ssl/.first`)
3. Create visible files through the hidden symlink (`./ssl/app.pem` ->
   `./ssl/..data/app.pem`)
4. When updating the key and certificate, write them into a new hidden
   directory (`./ssl/.second/app.pem` and `./ssl/.second/app.key`)
5. Create a new hidden symlink to this new directory (`./ssl/..data_new`
   -> `./ssl/.second`)
6. Finally, move this new hidden symlink over the old one (`mv
   ./ssl/..data_new ./ssl/..data`)
