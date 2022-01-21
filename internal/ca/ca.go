package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type CA struct {
	cert   *x509.Certificate
	signer interface{}
	pem    []byte
}

// New reads the CA certificate and key from the given path. The given file must contain exactly
// one PRIVATE KEY block and exactly one CERTIFICATE block.
func New(path string) (*CA, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certDER []byte
	var keyDER []byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("file %q didn't contain a CERTIFICATE and PRIVATE KEY", path)
		}
		switch block.Type {
		case "CERTIFICATE":
			certDER = block.Bytes
		case "PRIVATE KEY":
			keyDER = block.Bytes
		}
		if keyDER != nil && certDER != nil {
			break
		}
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, fmt.Errorf("the given certificate is not a CA cert")
	}

	signer, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return &CA{cert, signer, certPEM}, nil
}

type EndEntity struct {
	PKCS8 string `json:"pkcs8"`
	Chain string `json:"chain"`
}

type CertOption func(*x509.Certificate)

func WithValidity(d time.Duration) CertOption {
	now := time.Now()
	return func(cert *x509.Certificate) {
		cert.NotBefore = now
		cert.NotAfter = now.Add(d)
	}
}

// Sign generates a keypair and signs a certificate for the given host.
func (c *CA) Sign(host string, opts ...CertOption) (*EndEntity, error) {
	subjectPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(subjectPriv)
	if err != nil {
		return nil, err
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	// Sign the certificate.
	tmpl, err := endEntityTemplate(host, opts...)
	if err != nil {
		return nil, err
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, c.cert, subjectPriv.Public(), c.signer)
	if err != nil {
		return nil, err
	}

	// Encode the certificate chain.
	var chain bytes.Buffer
	if err := pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return nil, err
	}
	if _, err := chain.Write(c.pem); err != nil {
		return nil, err
	}

	return &EndEntity{
		Chain: chain.String(),
		PKCS8: string(pkcs8),
	}, nil
}

func endEntityTemplate(host string, opts ...CertOption) (*x509.Certificate, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}

	// Use a random SKID, since the RFC says end entity certs SHOULD
	// have one, but Go doesn't generate one. A random SKID makes it
	// unsafe to sign a new cert for this same key.
	skid := make([]byte, 20)
	if _, err := rand.Read(skid); err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 3, 0),
		Subject:      pkix.Name{CommonName: host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		SubjectKeyId: skid,
		DNSNames:     []string{host},
	}

	for _, opt := range opts {
		opt(tmpl)
	}

	return tmpl, nil
}
