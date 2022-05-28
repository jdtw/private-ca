package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"jdtw.dev/private-ca/internal/ca"
)

var (
	signerPath = flag.String("signer", "", "Path to CA certificate and key PEM file")
	host       = flag.String("host", "localhost", "Host to sign certificate for")
	out        = flag.String("out", "", "Output directory")
)

func main() {
	flag.Parse()

	signer, err := ca.New(*signerPath)
	if err != nil {
		log.Fatalf("failed to load %q: %v", *signerPath, err)
	}

	endEntity, err := signer.Sign(*host)
	if err != nil {
		log.Fatalf("failed to sign cert: %v", err)
	}

	if *out == "" {
		fmt.Print(endEntity.PKCS8)
		fmt.Print(endEntity.Chain)
		return
	}

	p := filepath.Join(*out, *host+".pem")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0400)
	defer f.Close()
	if err != nil {
		log.Fatalf("failed to open %q: %v", p, err)
	}
	if _, err := f.WriteString(endEntity.PKCS8); err != nil {
		log.Fatalf("failed to write to %q: %v", p, err)
	}
	if _, err := f.WriteString(endEntity.Chain); err != nil {
		log.Fatalf("failed to write to %q: %v", p, err)
	}
	fmt.Printf("Wrote %s\n", p)
}
