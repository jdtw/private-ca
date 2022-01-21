package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var (
	url         = flag.String("url", "", "Address")
	clientCert  = flag.String("pem", "", "Path to certificate and key PEM file")
	serverRoots = flag.String("ca", "", "Server roots")
)

func main() {
	flag.Parse()

	clientKeyPair, err := tls.LoadX509KeyPair(*clientCert, *clientCert)
	if err != nil {
		log.Fatalf("failed to load x509 key pair from %q, %q: %v", *clientCert, *clientCert, err)
	}

	pem, err := os.ReadFile(*serverRoots)
	if err != nil {
		log.Fatalf("failed to read roots from %q: %v", *serverRoots, err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(pem)

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{clientKeyPair},
				RootCAs:      certPool,
			},
		},
	}

	r, err := c.Get(*url + "/renew")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		log.Fatalf("Unexpected response status: %d %s", r.StatusCode, r.Status)
	}
	if ct := r.Header["Content-Type"]; len(ct) != 1 || ct[0] != "application/x-pem-file" {
		log.Fatalf("Got content-type %v, want application/x-pem-file", ct)
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("failed to read body: %v", err)
	}

	if err := os.Rename(*clientCert, *clientCert+".old"); err != nil {
		log.Fatalf("failed to rename %q: %v", *clientCert, err)
	}
	if err := os.WriteFile(*clientCert, body, 0400); err != nil {
		log.Fatalf("failed to write %q: %v", *clientCert, err)
	}
	fmt.Printf("Wrote %s\n", *clientCert)
}
