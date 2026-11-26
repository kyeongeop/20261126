package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"mirrorsync/internal/trust"
)

const certValidity = 10 * 365 * 24 * time.Hour

func cmdKeygen(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "subject", "key")
	if err != nil {
		return err
	}
	kf, _, err := trust.GenerateKey(flags["subject"])
	if err != nil {
		return err
	}
	if err := trust.SaveKey(flags["key"], kf); err != nil {
		return err
	}
	fmt.Printf("wrote Ed25519 key for %q to %s\n", flags["subject"], flags["key"])
	return nil
}

func cmdRootCert(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "key", "cert")
	if err != nil {
		return err
	}
	kf, priv, err := trust.LoadKey(flags["key"])
	if err != nil {
		return err
	}
	now := time.Now()
	cert, err := trust.NewRoot(kf.Subject, uint64(now.UnixNano()), priv, now, now.Add(certValidity))
	if err != nil {
		return err
	}
	return writeJSON(flags["cert"], cert)
}

func cmdIssueCert(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "ca-key", "ca-cert", "subject", "key", "cert")
	if err != nil {
		return err
	}
	_, caKey, err := trust.LoadKey(flags["ca-key"])
	if err != nil {
		return err
	}
	caCertData, err := os.ReadFile(flags["ca-cert"])
	if err != nil {
		return err
	}
	caCert, err := trust.DecodeCertificate(caCertData)
	if err != nil {
		return err
	}
	subjectKf, subjectPriv, err := trust.GenerateKey(flags["subject"])
	if err != nil {
		return err
	}
	if err := trust.SaveKey(flags["key"], subjectKf); err != nil {
		return err
	}
	pub := subjectPriv.Public().(ed25519.PublicKey)
	now := time.Now()
	cert, err := trust.IssueCert(flags["subject"], uint64(now.UnixNano()),
		flags["ca"] == "true", now, now.Add(certValidity), caCert, caKey, pub)
	if err != nil {
		return err
	}
	if err := writeJSON(flags["cert"], cert); err != nil {
		return err
	}
	fmt.Printf("wrote key %s and certificate %s\n", flags["key"], flags["cert"])
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}
