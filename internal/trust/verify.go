package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// VerifyEnvelope checks the complete signature chain for the given manifest:
//  1. the manifest digest recorded in the envelope matches the bytes,
//  2. the leaf Ed25519 signature over the manifest is valid,
//  3. every certificate signature chains up to the trusted root,
//  4. every certificate is within its validity window at time now.
func VerifyEnvelope(manifestBytes, envelopeBytes []byte, trustedRoot *Certificate, now time.Time) error {
	env, err := ParseEnvelope(envelopeBytes)
	if err != nil {
		return err
	}
	if env.Algorithm != AlgorithmEd25519 {
		return fmt.Errorf("unsupported signature algorithm %q", env.Algorithm)
	}
	sum := sha256.Sum256(manifestBytes)
	if got := hex.EncodeToString(sum[:]); got != env.ManifestSHA256 {
		return fmt.Errorf("manifest digest mismatch: envelope %s, actual %s", env.ManifestSHA256, got)
	}
	leaf, err := DecodeCertificate([]byte(env.SignerCert))
	if err != nil {
		return fmt.Errorf("signer certificate: %w", err)
	}
	chain := make([]*Certificate, 0, len(env.Chain))
	for i, raw := range env.Chain {
		c, certErr := DecodeCertificate([]byte(raw))
		if certErr != nil {
			return fmt.Errorf("chain certificate %d: %w", i, certErr)
		}
		chain = append(chain, c)
	}
	if err := VerifyChain(leaf, chain, trustedRoot, now); err != nil {
		return err
	}
	leafKey, err := leaf.Public()
	if err != nil {
		return err
	}
	sig, err := decodeB64(env.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !ed25519.Verify(leafKey, manifestBytes, sig) {
		return fmt.Errorf("manifest signature does not verify against leaf %q", leaf.Subject)
	}
	return nil
}

// VerifyChain walks leaf -> intermediates -> trusted root, verifying each
// certificate signature, CA flag, validity window and issuer linkage.
func VerifyChain(leaf *Certificate, chain []*Certificate, trustedRoot *Certificate, now time.Time) error {
	if trustedRoot == nil {
		return fmt.Errorf("a trusted root certificate is required")
	}
	if err := verifySelfSignedRoot(trustedRoot, now); err != nil {
		return err
	}
	cert := leaf
	for i := 0; ; i++ {
		if i >= len(chain) {
			return fmt.Errorf("certificate chain does not reach trusted root %q", trustedRoot.Subject)
		}
		issuer := chain[i]
		if cert.Issuer != issuer.Subject {
			return fmt.Errorf("certificate %q names issuer %q, next chain cert is %q",
				cert.Subject, cert.Issuer, issuer.Subject)
		}
		if !issuer.IsCA {
			return fmt.Errorf("issuer %q must be a CA certificate", issuer.Subject)
		}
		if err := VerifyCertificate(cert, issuer, now); err != nil {
			return err
		}
		if issuer.Subject == trustedRoot.Subject {
			if i+1 != len(chain) {
				return fmt.Errorf("chain continues after reaching root %q", trustedRoot.Subject)
			}
			if issuer.PublicKey != trustedRoot.PublicKey || issuer.Signature != trustedRoot.Signature {
				return fmt.Errorf("chain root %q differs from trusted root", issuer.Subject)
			}
			return nil
		}
		cert = issuer
	}
}

// VerifyCertificate checks one certificate against its issuing CA certificate.
func VerifyCertificate(cert, issuer *Certificate, now time.Time) error {
	if err := checkValidity(cert, now); err != nil {
		return err
	}
	issuerKey, err := issuer.Public()
	if err != nil {
		return err
	}
	payload, err := cert.SigningBytes()
	if err != nil {
		return err
	}
	sig, err := decodeB64(cert.Signature)
	if err != nil {
		return fmt.Errorf("certificate %q: invalid signature encoding: %w", cert.Subject, err)
	}
	if !ed25519.Verify(issuerKey, payload, sig) {
		return fmt.Errorf("certificate %q: signature failed verification against %q", cert.Subject, issuer.Subject)
	}
	return nil
}

func verifySelfSignedRoot(root *Certificate, now time.Time) error {
	if !root.IsCA {
		return fmt.Errorf("trusted root %q must be a CA certificate", root.Subject)
	}
	if root.Issuer != root.Subject {
		return fmt.Errorf("trusted root %q must be self-issued (issuer=%q)", root.Subject, root.Issuer)
	}
	return VerifyCertificate(root, root, now)
}

func checkValidity(cert *Certificate, now time.Time) error {
	notBefore, err := time.Parse(time.RFC3339, cert.NotBefore)
	if err != nil {
		return fmt.Errorf("certificate %q: invalid notBefore: %w", cert.Subject, err)
	}
	notAfter, err := time.Parse(time.RFC3339, cert.NotAfter)
	if err != nil {
		return fmt.Errorf("certificate %q: invalid notAfter: %w", cert.Subject, err)
	}
	if now.Before(notBefore) {
		return fmt.Errorf("certificate %q is not yet valid (notBefore %s)", cert.Subject, cert.NotBefore)
	}
	if now.After(notAfter) {
		return fmt.Errorf("certificate %q has expired (notAfter %s)", cert.Subject, cert.NotAfter)
	}
	return nil
}
