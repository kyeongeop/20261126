// Package envelope implements the authenticated encryption primitives used by
// the versioned file store. Every encryption operation uses AES-256-GCM with
// a fresh random 12-byte nonce; the nonce is prepended to the ciphertext so
// each blob is self-contained.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// ErrKeySize is returned when an AES-256 key does not contain 32 bytes.
var ErrKeySize = errors.New("envelope: key must be 32 bytes (AES-256)")

// GenerateKey returns a fresh cryptographically random AES-256 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Seal encrypts plaintext with key and returns nonce || ciphertext.
func Seal(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a blob produced by Seal and authenticates its GCM tag.
func Open(key, blob []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("envelope: ciphertext too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SHA256 returns the lowercase hex SHA-256 digest of data.
func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
