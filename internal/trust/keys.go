package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
)

// GenerateKey creates a new Ed25519 identity and returns its key file
// representation.
func GenerateKey(subject string) (*KeyFile, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	kf := &KeyFile{
		Subject:   subject,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Seed:      base64.StdEncoding.EncodeToString(priv.Seed()),
	}
	return kf, priv, nil
}

// PrivateKey recovers the Ed25519 private key from a key file.
func (k *KeyFile) PrivateKey() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(k.Seed)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SaveKey writes a key file with owner-only permissions.
func SaveKey(path string, kf *KeyFile) error {
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadKey reads a key file previously written by SaveKey.
func LoadKey(path string) (*KeyFile, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, nil, err
	}
	priv, err := kf.PrivateKey()
	if err != nil {
		return nil, nil, err
	}
	return &kf, priv, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
