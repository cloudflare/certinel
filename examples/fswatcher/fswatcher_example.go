package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"

	"github.com/pantheon-systems/certinel"
	"github.com/pantheon-systems/certinel/fswatcher"
)

func main() {
	// logger is optional. If you don't want the certinel object to log, pass nil to certinel.New()
	logger := log.New(os.Stderr, "", log.LstdFlags)

	watcher, err := fswatcher.New("tls.crt", "tls.key")
	if err != nil {
		log.Fatalf("fatal: unable to read server certificate. err='%s'", err)
	}

	sentinel := certinel.New(watcher, logger, func(err error) {
		log.Printf("error: certinel was unable to reload the certificate. err='%s'", err)
	})

	sentinel.Watch()

	server := http.Server{
		Addr: ":8000",
		TLSConfig: &tls.Config{
			GetCertificate: sentinel.GetCertificate,
		},
	}

	logger.Println("listening on 8000")
	logger.Fatal(server.ListenAndServeTLS("", ""))
}
