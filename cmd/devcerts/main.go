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
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type certificateSpec struct {
	fileName string
	common   string
	dnsNames []string
	org      string
}

func main() {
	outDir := flag.String("out", "certs", "output directory")
	flag.Parse()

	if err := generate(*outDir); err != nil {
		fmt.Fprintf(os.Stderr, "generate development certificates: %v\n", err)
		os.Exit(1)
	}
}

func generate(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().Add(-time.Hour)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Local Dev CA", Organization: []string{"SNI Gateway Dev"}},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(outDir, "ca.pem"), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}

	specs := []certificateSpec{
		{fileName: "exact-shop", common: "shop.example.com", dnsNames: []string{"shop.example.com"}, org: "Exact Route"},
		{fileName: "wildcard-example", common: "*.example.com", dnsNames: []string{"*.example.com"}, org: "Wildcard Route"},
		{fileName: "default", common: "default.local", dnsNames: []string{"default.local"}, org: "Default Certificate"},
	}
	for index, spec := range specs {
		if err := issueLeaf(outDir, caCert, caKey, spec, int64(index+2), now); err != nil {
			return err
		}
	}
	return nil
}

func issueLeaf(outDir string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spec certificateSpec, serial int64, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   spec.common,
			Organization: []string{spec.org},
		},
		DNSNames:              spec.dnsNames,
		NotBefore:             now,
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	certPath := filepath.Join(outDir, spec.fileName+".pem")
	keyPath := filepath.Join(outDir, spec.fileName+"-key.pem")
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	return nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	block := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if block == nil {
		return fmt.Errorf("encode PEM for %q", path)
	}
	if err := os.WriteFile(path, block, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
