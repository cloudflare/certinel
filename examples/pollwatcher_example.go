package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/pantheon-systems/certinel"
	"github.com/pantheon-systems/certinel/pollwatcher"
)

var interval = 5 * time.Second // NOTE: 5 seconds is fairly short for demonstration purposes.
// You should probably use a longer interval in production. One to five minutes sounds about right.

func main() {
	watcher := pollwatcher.New("tls.crt", "tls.key", interval)
	sentinel := certinel.New(watcher, func(err error) {
		log.Fatalf("error: certinel was unable to reload the certificate. err='%s'", err)
	})

	sentinel.Watch()

	// Uncomment to simulate shutting down the certinel
	// time.Sleep(2 * time.Second)
	// sentinel.Close()

	server := http.Server{
		Addr: ":8000",
		TLSConfig: &tls.Config{
			GetCertificate: sentinel.GetCertificate,
		},
	}

	log.Println("listening on 8000")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
