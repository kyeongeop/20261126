// Package token implements scoped access tokens for the internal
// package registry. A token is bound to an explicit set of actions,
// a namespace prefix, and an optional package name pattern.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
)

// Action is an operation a token may allow.
type Action string

const (
	ActionRead    Action = "read"
	ActionPublish Action = "publish"
	ActionRevoke  Action = "revoke"
)

// Purpose is a named preset that maps to an explicit action set.
type Purpose string

const (
	PurposeReadOnly Purpose = "readonly"
	PurposePublish  Purpose = "publish"
	PurposeRevoke   Purpose = "revoke"
)

// ActionsForPurpose expands a purpose preset into its action set.
func ActionsForPurpose(p Purpose) ([]Action, error) {
	switch p {
	case PurposeReadOnly:
		return []Action{ActionRead}, nil
	case PurposePublish:
		return []Action{ActionPublish}, nil
	case PurposeRevoke:
		return []Action{ActionRevoke}, nil
	default:
		return nil, fmt.Errorf("unknown purpose %q (want readonly, publish or revoke)", p)
	}
}

// Scope restricts what a token may do.
type Scope struct {
	// Actions is the explicit list of allowed operations.
	Actions []Action `json:"actions"`
	// NamespacePrefix limits the token to namespaces with this prefix,
	// e.g. "acme/". An empty prefix matches nothing.
	NamespacePrefix string `json:"namespace_prefix"`
	// PackagePattern is an optional path.Match glob applied to the full
	// package name "namespace/name", e.g. "acme/billing-*".
	PackagePattern string `json:"package_pattern,omitempty"`
}

// Validate checks the scope is well formed.
func (s Scope) Validate() error {
	if len(s.Actions) == 0 {
		return errors.New("scope must allow at least one action")
	}
	for _, a := range s.Actions {
		switch a {
		case ActionRead, ActionPublish, ActionRevoke:
		default:
			return fmt.Errorf("unknown action %q", a)
		}
	}
	if s.NamespacePrefix == "" {
		return errors.New("namespace_prefix is required; tokens are never global")
	}
	if strings.Contains(s.NamespacePrefix, "..") {
		return errors.New("namespace_prefix must not contain '..'")
	}
	if s.PackagePattern != "" {
		if _, err := path.Match(s.PackagePattern, ""); err != nil {
			return fmt.Errorf("invalid package_pattern: %w", err)
		}
	}
	return nil
}

// Allows reports whether the scope permits action on namespace/name.
func (s Scope) Allows(action Action, namespace, name string) bool {
	actionOK := false
	for _, a := range s.Actions {
		if a == action {
			actionOK = true
			break
		}
	}
	if !actionOK {
		return false
	}
	if !strings.HasPrefix(namespace, s.NamespacePrefix) {
		return false
	}
	if s.PackagePattern != "" {
		full := strings.TrimSuffix(namespace, "/") + "/" + name
		ok, err := path.Match(s.PackagePattern, full)
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// NewSecret generates a new opaque token secret.
func NewSecret() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "ireg_" + hex.EncodeToString(buf[:]), nil
}

// HashSecret returns the hex sha256 of a secret; only hashes are stored.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
