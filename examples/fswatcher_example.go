package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/pantheon-systems/certinel"
	"github.com/pantheon-systems/certinel/fswatcher"
)

func main() {
	watcher, err := fswatcher.New("tls.crt", "tls.key")
	if err != nil {
		log.Fatalf("fatal: unable to read server certificate. err='%s'", err)
	}
	sentinel := certinel.New(watcher, func(err error) {
		log.Printf("error: certinel was unable to reload the certificate. err='%s'", err)
	})

	sentinel.Watch()

	server := http.Server{
		Addr: ":8000",
		TLSConfig: &tls.Config{
			GetCertificate: sentinel.GetCertificate,
		},
	}

	log.Println("listening on 8000")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
