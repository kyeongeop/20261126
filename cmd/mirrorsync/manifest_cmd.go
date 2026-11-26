package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"mirrorsync/internal/manifest"
	"mirrorsync/internal/trust"
)

func cmdBuild(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "image", "image-id", "manifest")
	if err != nil {
		return err
	}
	m, err := manifest.Build(flags["image"], flags["image-id"])
	if err != nil {
		return err
	}
	data, err := m.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(flags["manifest"], data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote manifest with %d packages, rootHash %s\n", len(m.Packages), m.RootHash)
	return nil
}

func cmdSign(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "key", "cert", "chain", "manifest", "signature")
	if err != nil {
		return err
	}
	_, leafKey, err := trust.LoadKey(flags["key"])
	if err != nil {
		return err
	}
	leaf, err := loadCert(flags["cert"])
	if err != nil {
		return err
	}
	var chain []*trust.Certificate
	for _, p := range strings.Split(flags["chain"], ",") {
		c, certErr := loadCert(strings.TrimSpace(p))
		if certErr != nil {
			return certErr
		}
		chain = append(chain, c)
	}
	manifestBytes, err := os.ReadFile(flags["manifest"])
	if err != nil {
		return err
	}
	if _, err := manifest.Parse(manifestBytes); err != nil {
		return fmt.Errorf("refusing to sign invalid manifest: %w", err)
	}
	env, err := trust.SignManifest(manifestBytes, leafKey, leaf, chain)
	if err != nil {
		return err
	}
	data, err := env.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(flags["signature"], data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote signature envelope %s\n", flags["signature"])
	return nil
}

func loadCert(path string) (*trust.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return trust.DecodeCertificate(data)
}

// verifySignature is shared by the verify and sync commands.
func verifySignature(manifestBytes []byte, flags map[string]string) error {
	if flags["signature"] == "" && flags["root-cert"] == "" {
		return nil
	}
	if flags["signature"] == "" || flags["root-cert"] == "" {
		return fmt.Errorf("--signature and --root-cert must be provided together")
	}
	envelopeBytes, err := os.ReadFile(flags["signature"])
	if err != nil {
		return err
	}
	root, err := loadCert(flags["root-cert"])
	if err != nil {
		return err
	}
	return trust.VerifyEnvelope(manifestBytes, envelopeBytes, root, time.Now())
}

func cmdVerify(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "image", "manifest")
	if err != nil {
		return err
	}
	m, manifestBytes, err := loadManifest(flags["manifest"])
	if err != nil {
		return err
	}
	if err := verifySignature(manifestBytes, flags); err != nil {
		return err
	}
	report, err := verifyAndPrint(flags["image"], m)
	if err != nil {
		return err
	}
	if report.Problems() {
		os.Exit(3)
	}
	return nil
}

func loadManifest(path string) (*manifest.Manifest, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	m, err := manifest.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return m, data, nil
}
