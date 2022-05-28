package main

import (
	"crypto/tls"
	"log"
	"sync"
	"time"

	"jdtw.dev/private-ca/internal/ca"
)

// serverCert is an ephemeral TLS server certificate, signed by the CA.
type serverCert struct {
	host    string
	ca      *ca.CA
	keyPair *tls.Certificate
	sync.RWMutex
}

// NewServerCert returns a server cert struct with an ephemeral key pair
// for the given host. The certificate is valid for 24 hours and renews
// every 11 hours (allowing for two renewal attempts within the validity
// period).
func NewServerCert(host string, ca *ca.CA) (*serverCert, error) {
	var sc serverCert
	sc.host = host
	sc.ca = ca

	if err := sc.sign(); err != nil {
		return nil, err
	}

	t := time.NewTicker(11 * time.Hour)
	go func() {
		for {
			select {
			case <-t.C:
				if err := sc.sign(); err != nil {
					log.Printf("failed to renew cert: %v", err)
				} else {
					log.Printf("renewed server certificate")
				}
			}
		}
	}()

	return &sc, nil
}

func (sc *serverCert) Get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sc.RLock()
	defer sc.RUnlock()
	return sc.keyPair, nil
}

func (sc *serverCert) sign() error {
	ee, err := sc.ca.Sign(sc.host, ca.WithValidity(24*time.Hour))
	if err != nil {
		return err
	}
	kp, err := tls.X509KeyPair([]byte(ee.Chain), []byte(ee.PKCS8))
	if err != nil {
		return err
	}
	sc.Lock()
	defer sc.Unlock()
	sc.keyPair = &kp
	return nil
}
