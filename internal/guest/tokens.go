package guest

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const defaultPasscodeRounds = 120_000

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomSalt() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func newCredential() (id, rawToken, tokenHash string, err error) {
	id, err = randomID()
	if err != nil {
		return "", "", "", err
	}
	secret, err := randomSecret()
	if err != nil {
		return "", "", "", err
	}
	return id, id + "." + secret, hashString(secret), nil
}

func splitToken(raw string) (id, secret string, ok bool) {
	id, secret, found := strings.Cut(raw, ".")
	if !found || id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func hashPasscode(salt, passcode string, rounds int) string {
	if rounds <= 0 {
		rounds = defaultPasscodeRounds
	}
	key, _ := pbkdf2.Key(sha256.New, passcode, []byte(salt), rounds, sha256.Size)
	return hex.EncodeToString(key)
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func verifySecret(rawToken, expectedHash string) (string, bool) {
	id, secret, ok := splitToken(rawToken)
	if !ok || !constantTimeEqual(hashString(secret), expectedHash) {
		return "", false
	}
	return id, true
}
