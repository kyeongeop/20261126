package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"strings"
)

var (
	errNoCredentials  = errors.New("authentication required")
	errBadCredentials = errors.New("invalid credentials")
	errForbidden      = errors.New("forbidden")
)

type principal struct {
	User string
	Role string
}

type authConfig struct {
	users        map[string]credential
	trustHeaders bool
}

type credential struct {
	passwordHash [32]byte
	role         string
}

func newAuthConfig() *authConfig {
	config := &authConfig{
		users:        make(map[string]credential),
		trustHeaders: truthy(os.Getenv("PKG_TRUST_IDENTITY_HEADERS")),
	}
	spec := strings.TrimSpace(os.Getenv("PKG_USERS"))
	if spec == "" {
		spec = "publisher:publisher-pass:publisher,admin:admin-pass:admin"
	}
	for _, entry := range strings.Split(spec, ",") {
		parts := strings.Split(entry, ":")
		if len(parts) != 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		role := strings.TrimSpace(parts[2])
		if name == "" || parts[1] == "" || (role != rolePublisher && role != roleAdmin) {
			continue
		}
		config.users[name] = credential{
			passwordHash: sha256.Sum256([]byte(parts[1])),
			role:         role,
		}
	}
	return config
}

func (a *authConfig) authenticate(r *http.Request) (principal, error) {
	if a.trustHeaders {
		user := strings.TrimSpace(r.Header.Get("X-Authenticated-User"))
		role := strings.TrimSpace(r.Header.Get("X-Authenticated-Role"))
		if user != "" {
			if role != rolePublisher && role != roleAdmin {
				return principal{}, errBadCredentials
			}
			return principal{User: user, Role: role}, nil
		}
	}

	user, password, ok := r.BasicAuth()
	if !ok {
		return principal{}, errNoCredentials
	}
	stored, exists := a.users[user]
	if !exists {
		return principal{}, errBadCredentials
	}
	hash := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(hash[:], stored.passwordHash[:]) != 1 {
		return principal{}, errBadCredentials
	}
	return principal{User: user, Role: stored.role}, nil
}

func (a *authConfig) requireRole(r *http.Request, role string) (principal, error) {
	user, err := a.authenticate(r)
	if err != nil {
		return principal{}, err
	}
	if role != "" && user.Role != role {
		return principal{}, errForbidden
	}
	return user, nil
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
