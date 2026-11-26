package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Notification carries the single-use recovery credential to a user. The
// token is delivered out of band and is never returned through the HTTP API.
type Notification struct {
	UserID      string
	Method      NotifyMethod
	Destination string
	RequestID   string
	Token       string
	ExpiresAt   string
}

// Notifier delivers recovery notifications. Production deployments provide
// an email/SMS backend; tests use RecordingNotifier, which keeps everything
// in memory and needs no external service.
type Notifier interface {
	Send(Notification) error
}

// RecordingNotifier stores notifications in memory.
type RecordingNotifier struct {
	items []Notification
}

// NewRecordingNotifier builds an in-memory Notifier.
func NewRecordingNotifier() *RecordingNotifier {
	return &RecordingNotifier{}
}

// Send records the notification.
func (n *RecordingNotifier) Send(note Notification) error {
	n.items = append(n.items, note)
	return nil
}

// LastTokenFor returns the most recent token delivered to the user, or
// ErrNotFound if no notification exists.
func (n *RecordingNotifier) LastTokenFor(userID string) (string, error) {
	for i := len(n.items) - 1; i >= 0; i-- {
		if n.items[i].UserID == userID {
			return n.items[i].Token, nil
		}
	}
	return "", ErrNotFound
}

// All returns a copy of every recorded notification.
func (n *RecordingNotifier) All() []Notification {
	out := make([]Notification, len(n.items))
	copy(out, n.items)
	return out
}

// newRecoveryToken generates a high-entropy single-use token using
// crypto/rand and returns the plaintext token together with its SHA-256
// hash. Only the hash is stored.
func newRecoveryToken() (plaintext, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("mfa: generate recovery token: %w", err)
	}
	plaintext = hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, hex.EncodeToString(sum[:]), nil
}

// hashRecoveryToken hashes a token presented by the user.
func hashRecoveryToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
