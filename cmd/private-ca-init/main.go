package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	domain = flag.String("domain", "localhost", "Domain to use as a DNS constraint")
	rootID = flag.Int("root-id", 1, "Identifier for the root CA's CN (<domain> Root <ID>)")
	out    = flag.String("out", "", "Output directory")
)

func main() {
	flag.Parse()

	if *domain == "" {
		log.Fatalf("missing domain flag")
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0)

	rootCN := fmt.Sprintf("%s Root %d", *domain, *rootID)
	rootTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		Subject:               pkix.Name{CommonName: rootCN},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate root key: %v", err)
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootPriv.Public(), rootPriv)
	if err != nil {
		log.Fatalf("failed to sign %s: %v", rootCN, err)
	}

	rootTmpl, err = x509.ParseCertificate(rootDER)
	if err != nil {
		log.Fatalf("failed to parse root DER: %v", err)
	}

	domainCN := fmt.Sprintf("%s CA", *domain)
	domainTmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		Subject:               pkix.Name{CommonName: domainCN},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{*domain},
	}

	domainPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate domain key: %v", err)
	}

	domainDER, err := x509.CreateCertificate(rand.Reader, domainTmpl, rootTmpl, domainPriv.Public(), rootPriv)
	if err != nil {
		log.Fatalf("failed to sign %s: %v", domainCN, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(domainPriv)
	if err != nil {
		log.Fatalf("failed to marshal private key: %v", err)
	}

	rootPath := filepath.Join(*out, "root.pem")
	root, err := os.Create(rootPath)
	if err != nil {
		log.Fatalf("failed to create %q: %v", rootPath, err)
	}
	defer root.Close()

	caPath := filepath.Join(*out, *domain+".ca.pem")
	ca, err := os.OpenFile(caPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		log.Fatalf("failed to create %q: %v", caPath, err)
	}

	if err := pem.Encode(root, &pem.Block{Type: "CERTIFICATE", Bytes: rootDER}); err != nil {
		log.Fatalf("failed to encode root PEM: %v", err)
	}
	if err := root.Close(); err != nil {
		log.Fatalf("failed to close %q: %v", rootPath, err)
	}
	fmt.Printf("Wrote %s\n", rootPath)

	if err := pem.Encode(ca, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		log.Fatalf("failed to encode CA key: %v", err)
	}
	if err := pem.Encode(ca, &pem.Block{Type: "CERTIFICATE", Bytes: domainDER}); err != nil {
		log.Fatalf("failed to encode CA cert: %v", err)
	}
	if err := ca.Close(); err != nil {
		log.Fatalf("failed to close %q: %v", caPath, err)
	}
	fmt.Printf("Wrote %s\n", caPath)
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	i, err := rand.Int(rand.Reader, limit)
	if err != nil {
		log.Fatalf("failed to generate random serial: %v", err)
	}
	return i
}
