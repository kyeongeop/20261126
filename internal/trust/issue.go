package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

func timeString(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// NewRoot creates a self-signed root certificate for the given CA key.
func NewRoot(subject string, serial uint64, key ed25519.PrivateKey, notBefore, notAfter time.Time) (*Certificate, error) {
	cert := &Certificate{
		Subject:   subject,
		PublicKey: b64(key.Public().(ed25519.PublicKey)),
		Issuer:    subject,
		Serial:    serial,
		IsCA:      true,
		NotBefore: timeString(notBefore),
		NotAfter:  timeString(notAfter),
	}
	if err := signCert(cert, key); err != nil {
		return nil, err
	}
	return cert, nil
}

// IssueCert signs a new certificate with the issuer CA key.
func IssueCert(subject string, serial uint64, isCA bool, notBefore, notAfter time.Time,
	issuer *Certificate, issuerKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (*Certificate, error) {
	if issuer == nil {
		return nil, fmt.Errorf("issuer certificate is required")
	}
	if !issuer.IsCA {
		return nil, fmt.Errorf("issuer %q is not a CA certificate", issuer.Subject)
	}
	cert := &Certificate{
		Subject:   subject,
		PublicKey: b64(publicKey),
		Issuer:    issuer.Subject,
		Serial:    serial,
		IsCA:      isCA,
		NotBefore: timeString(notBefore),
		NotAfter:  timeString(notAfter),
	}
	if err := signCert(cert, issuerKey); err != nil {
		return nil, err
	}
	return cert, nil
}

func signCert(cert *Certificate, key ed25519.PrivateKey) error {
	payload, err := cert.SigningBytes()
	if err != nil {
		return err
	}
	cert.Signature = b64(ed25519.Sign(key, payload))
	return nil
}

// SignManifest builds a signed envelope over the exact manifest bytes.
// chainCerts must run from the certificate directly above the leaf up to and
// including the trusted root certificate.
func SignManifest(manifestBytes []byte, leafKey ed25519.PrivateKey, leaf *Certificate, chainCerts []*Certificate) (*Envelope, error) {
	sum := sha256.Sum256(manifestBytes)
	chain := make([]string, 0, len(chainCerts))
	for _, c := range chainCerts {
		data, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		chain = append(chain, string(data))
	}
	leafData, err := json.Marshal(leaf)
	if err != nil {
		return nil, err
	}
	env := &Envelope{
		Algorithm:      AlgorithmEd25519,
		ManifestSHA256: hex.EncodeToString(sum[:]),
		SignerCert:     string(leafData),
		Chain:          chain,
	}
	env.Signature = b64(ed25519.Sign(leafKey, manifestBytes))
	return env, nil
}

// Marshal serializes an envelope to JSON.
func (e *Envelope) Marshal() ([]byte, error) { return json.MarshalIndent(e, "", "  ") }

// ParseEnvelope decodes a signature envelope.
func ParseEnvelope(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("invalid signature envelope JSON: %w", err)
	}
	return &e, nil
}
