package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jdtw/private-ca/internal/ca"
)

var (
	port = flag.Int("port", 8080, "Port to listen on")

	// The signer cert/key are used to sign certificates given out by this CA.
	signerPath = flag.String("signer", "", "Path to private key and certificate PEM file")

	// The server cert/key and client roots are for mTLS.
	host        = flag.String("host", "localhost", "Server's hostname. Used in this server's TLS certificate.")
	clientRoots = flag.String("client-roots", "", "Roots to verify the client cert against")
)

func main() {
	flag.Parse()

	pem, err := os.ReadFile(*clientRoots)
	if err != nil {
		log.Fatalf("failed to read %q: %v", *clientRoots, err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		log.Fatal("failed to add certs to pool")
	}

	signer, err := ca.New(*signerPath)
	if err != nil {
		log.Fatalf("failed to load CA from %q: %v", *signerPath, err)
	}

	serverCert, err := NewServerCert(*host, signer)

	h := &handler{signer, http.NewServeMux()}
	h.HandleFunc("/renew", h.sign())

	s := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: h,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: serverCert.Get,
			ClientCAs:      certPool,
			ClientAuth:     tls.RequireAndVerifyClientCert,
		},
	}

	log.Fatal(s.ListenAndServeTLS("", ""))
}

type handler struct {
	ca *ca.CA
	*http.ServeMux
}

func (h *handler) sign() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}

		leaf := r.TLS.VerifiedChains[0][0]
		if len(leaf.DNSNames) != 1 {
			http.Error(w, "expected exactly one DNS SAN", http.StatusBadRequest)
			return
		}

		host := leaf.DNSNames[0]
		ee, err := h.ca.Sign(host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		if _, err := w.Write([]byte(ee.PKCS8)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := w.Write([]byte(ee.Chain)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("signed cert for %s", host)
	}
}
