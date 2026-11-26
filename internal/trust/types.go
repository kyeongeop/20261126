package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// AlgorithmEd25519 is the only signature algorithm supported.
const AlgorithmEd25519 = "ed25519"

// Certificate is a lightweight, self-contained public-key certificate.
// Root certificates are self-issued (Issuer == Subject); every other
// certificate is signed by its issuer's Ed25519 key.
type Certificate struct {
	Subject   string `json:"subject"`
	PublicKey string `json:"publicKey"`
	Issuer    string `json:"issuer"`
	Serial    uint64 `json:"serial"`
	IsCA      bool   `json:"isCA"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	// Signature is base64 Ed25519 over the canonical payload bytes.
	Signature string `json:"signature"`
}

// Envelope binds a manifest to the leaf certificate that signed it and to the
// certificates needed to reach the trusted root.
type Envelope struct {
	Algorithm      string   `json:"algorithm"`
	ManifestSHA256 string   `json:"manifestSha256"`
	SignerCert     string   `json:"signerCert"`
	Chain          []string `json:"chain"`
	Signature      string   `json:"signature"`
}

// KeyFile is the on-disk representation of an Ed25519 private key. The seed
// is sensitive and must be protected with file system permissions.
type KeyFile struct {
	Subject   string `json:"subject"`
	PublicKey string `json:"publicKey"`
	Seed      string `json:"seed"`
}

type certPayload struct {
	Subject   string `json:"subject"`
	PublicKey string `json:"publicKey"`
	Issuer    string `json:"issuer"`
	Serial    uint64 `json:"serial"`
	IsCA      bool   `json:"isCA"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

func (c *Certificate) payload() certPayload {
	return certPayload{
		Subject:   c.Subject,
		PublicKey: c.PublicKey,
		Issuer:    c.Issuer,
		Serial:    c.Serial,
		IsCA:      c.IsCA,
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
	}
}

// SigningBytes returns the deterministic byte sequence covered by the
// certificate signature. Go marshals struct fields in declaration order,
// which makes this representation stable across machines.
func (c *Certificate) SigningBytes() ([]byte, error) {
	return json.Marshal(c.payload())
}

// Public decodes the base64 Ed25519 public key.
func (c *Certificate) Public() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("certificate %q: invalid public key encoding: %w", c.Subject, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("certificate %q: public key must be %d bytes", c.Subject, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// DecodeCertificate parses one JSON certificate.
func DecodeCertificate(data []byte) (*Certificate, error) {
	var c Certificate
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("invalid certificate JSON: %w", err)
	}
	return &c, nil
}
