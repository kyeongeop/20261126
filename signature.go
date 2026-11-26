package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const signatureAlgorithm = "HMAC-SHA256"

type signer struct {
	key   []byte
	keyID string
}

func loadSigner(dataDir string) (*signer, error) {
	keyPath := filepath.Join(dataDir, "signing.key")
	key, err := os.ReadFile(keyPath)
	if err == nil {
		if len(key) < 32 {
			return nil, fmt.Errorf("signing key is too short")
		}
		return newSigner(key), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			existing, readErr := os.ReadFile(keyPath)
			if readErr != nil {
				return nil, fmt.Errorf("read concurrent signing key: %w", readErr)
			}
			if len(existing) < 32 {
				return nil, fmt.Errorf("concurrent signing key is too short")
			}
			return newSigner(existing), nil
		}
		return nil, fmt.Errorf("create signing key: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write signing key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close signing key: %w", err)
	}
	return newSigner(key), nil
}

func newSigner(key []byte) *signer {
	sum := sha256.Sum256(append([]byte("key-id:"), key...))
	return &signer{key: key, keyID: hex.EncodeToString(sum[:])[:16]}
}

func (s *signer) sign(release Release, at time.Time) (Signature, error) {
	release.Signature = Signature{
		Algorithm: signatureAlgorithm,
		KeyID:     s.keyID,
		SignedAt:  at.UTC(),
	}
	payload, err := release.signedPayload()
	if err != nil {
		return Signature{}, fmt.Errorf("serialize signed payload: %w", err)
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	return Signature{
		Algorithm: signatureAlgorithm,
		KeyID:     s.keyID,
		Value:     base64.RawStdEncoding.EncodeToString(mac.Sum(nil)),
		SignedAt:  at.UTC(),
	}, nil
}

func (s *signer) verify(release Release) bool {
	if release.Signature.Algorithm != signatureAlgorithm || release.Signature.KeyID != s.keyID {
		return false
	}
	payload, err := release.signedPayload()
	if err != nil {
		return false
	}
	provided, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(release.Signature.Value))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	return hmac.Equal(provided, mac.Sum(nil))
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestHex(digest string) (string, bool) {
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) {
		return "", false
	}
	value := strings.TrimPrefix(digest, prefix)
	if len(value) != sha256.Size*2 {
		return "", false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", false
	}
	return strings.ToLower(value), true
}
