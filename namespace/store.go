package namespace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Store struct {
	mu    sync.RWMutex
	state State
	path  string
}

func OpenStore(statePath, fixturePath string) (*Store, error) {
	var state State
	data, err := os.ReadFile(statePath)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, fmt.Errorf("decode state %s: %w", statePath, err)
		}
	case os.IsNotExist(err):
		data, err = os.ReadFile(fixturePath)
		if err != nil {
			return nil, fmt.Errorf("read fixture %s: %w", fixturePath, err)
		}
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, fmt.Errorf("decode fixture %s: %w", fixturePath, err)
		}
	default:
		return nil, fmt.Errorf("read state %s: %w", statePath, err)
	}
	if err := normalizeAndValidateState(&state); err != nil {
		return nil, err
	}
	store := &Store{state: state, path: statePath}
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		if err := store.persist(state); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func NewStore(initial State, path string) (*Store, error) {
	if err := normalizeAndValidateState(&initial); err != nil {
		return nil, err
	}
	return &Store{state: initial, path: path}, nil
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func (s *Store) Update(change func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := cloneState(s.state)
	if err := change(&next); err != nil {
		return err
	}
	if err := normalizeAndValidateState(&next); err != nil {
		return err
	}
	if s.path != "" {
		if err := s.persist(next); err != nil {
			return fmt.Errorf("persist state: %w", err)
		}
	}
	s.state = next
	return nil
}

func (s *Store) persist(state State) error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func cloneState(state State) State {
	payload, err := json.Marshal(state)
	if err != nil {
		panic(fmt.Sprintf("clone state: %v", err))
	}
	var clone State
	if err := json.Unmarshal(payload, &clone); err != nil {
		panic(fmt.Sprintf("clone state: %v", err))
	}
	return clone
}

func normalizeAndValidateState(state *State) error {
	if state.SchemaVersion == 0 {
		state.SchemaVersion = SchemaVersion
	}
	if state.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported state schema version %d", state.SchemaVersion)
	}
	state.Policy = state.Policy.normalized()
	if state.Namespaces == nil {
		state.Namespaces = make(map[string]Namespace)
	}
	if state.Packages == nil {
		state.Packages = make(map[string][]Package)
	}

	seenUsers := make(map[string]struct{}, len(state.Users))
	seenTokens := make(map[string]struct{}, len(state.Users))
	for i := range state.Users {
		user := &state.Users[i]
		user.ID = strings.TrimSpace(user.ID)
		user.Name = strings.TrimSpace(user.Name)
		user.Role = strings.TrimSpace(strings.ToLower(user.Role))
		user.TokenSHA256 = strings.ToLower(strings.TrimSpace(user.TokenSHA256))
		if user.ID == "" || user.Name == "" {
			return fmt.Errorf("user id and name are required")
		}
		if user.Role != RolePublisher && user.Role != RoleAdmin {
			return fmt.Errorf("user %s has unsupported role %q", user.ID, user.Role)
		}
		if len(user.TokenSHA256) != sha256.Size*2 {
			return fmt.Errorf("user %s has invalid token_sha256", user.ID)
		}
		if _, err := hex.DecodeString(user.TokenSHA256); err != nil {
			return fmt.Errorf("user %s has invalid token_sha256: %w", user.ID, err)
		}
		if _, exists := seenUsers[user.ID]; exists {
			return fmt.Errorf("duplicate user %s", user.ID)
		}
		if _, exists := seenTokens[user.TokenSHA256]; exists {
			return fmt.Errorf("duplicate token hash for user %s", user.ID)
		}
		seenUsers[user.ID] = struct{}{}
		seenTokens[user.TokenSHA256] = struct{}{}
	}

	users := make(map[string]User, len(state.Users))
	for _, user := range state.Users {
		users[user.ID] = user
	}
	for name, ns := range state.Namespaces {
		if err := validateNamespaceName(name); err != nil {
			return fmt.Errorf("namespace %q: %w", name, err)
		}
		if ns.Name == "" {
			ns.Name = name
		}
		if ns.Name != name {
			return fmt.Errorf("namespace map key %q does not match record name %q", name, ns.Name)
		}
		switch ns.State {
		case NamespaceReserved:
			if ns.OwnerID == "" {
				return fmt.Errorf("reserved namespace %s has no owner", name)
			}
			if _, ok := users[ns.OwnerID]; !ok {
				return fmt.Errorf("namespace %s refers to unknown owner %s", name, ns.OwnerID)
			}
			if ns.ReservedUntil.IsZero() {
				return fmt.Errorf("reserved namespace %s has no reservation deadline", name)
			}
		case NamespaceExpired, NamespaceLocked:
			if ns.OwnerID != "" {
				return fmt.Errorf("namespace %s in state %s cannot have an owner", name, ns.State)
			}
		default:
			return fmt.Errorf("namespace %s has unsupported state %q", name, ns.State)
		}
		state.Namespaces[name] = ns
	}

	for namespaceName, packages := range state.Packages {
		ns, ok := state.Namespaces[namespaceName]
		if !ok {
			return fmt.Errorf("package list refers to unknown namespace %s", namespaceName)
		}
		for i := range packages {
			pkg := &packages[i]
			if pkg.Namespace == "" {
				pkg.Namespace = namespaceName
			}
			if pkg.Namespace != namespaceName {
				return fmt.Errorf("package namespace %q does not match map key %q", pkg.Namespace, namespaceName)
			}
			if err := validatePackagePart(pkg.Name); err != nil {
				return fmt.Errorf("package %s/%s: %w", namespaceName, pkg.Name, err)
			}
			if err := validateVersion(pkg.Version); err != nil {
				return fmt.Errorf("package %s/%s@%s: %w", namespaceName, pkg.Name, pkg.Version, err)
			}
		}
		if len(packages) > 0 && ns.State == NamespaceExpired {
			return fmt.Errorf("expired namespace %s cannot contain packages", namespaceName)
		}
		if len(packages) > 0 && ns.State == NamespaceReserved && ns.OwnerID == "" {
			return fmt.Errorf("namespace %s contains packages without an owner", namespaceName)
		}
		state.Packages[namespaceName] = packages
	}
	if len(state.Packages[""]) > 0 {
		delete(state.Packages, "")
	}

	seenClaims := make(map[string]struct{}, len(state.Claims))
	activeClaimNamespaces := make(map[string]string)
	for i := range state.Claims {
		claim := &state.Claims[i]
		claim.ID = strings.TrimSpace(claim.ID)
		claim.Namespace = strings.TrimSpace(claim.Namespace)
		if claim.ID == "" {
			return fmt.Errorf("claim id is required")
		}
		if _, exists := seenClaims[claim.ID]; exists {
			return fmt.Errorf("duplicate claim id %s", claim.ID)
		}
		if err := validateNamespaceName(claim.Namespace); err != nil {
			return fmt.Errorf("claim %s: %w", claim.ID, err)
		}
		if _, ok := users[claim.ClaimantID]; !ok {
			return fmt.Errorf("claim %s refers to unknown claimant %s", claim.ID, claim.ClaimantID)
		}
		switch claim.Status {
		case ClaimPending:
			if claim.HoldUntil.IsZero() {
				return fmt.Errorf("pending claim %s has no hold deadline", claim.ID)
			}
			if other, exists := activeClaimNamespaces[claim.Namespace]; exists {
				return fmt.Errorf("pending claims %s and %s both hold namespace %s", other, claim.ID, claim.Namespace)
			}
			activeClaimNamespaces[claim.Namespace] = claim.ID
		case ClaimApproved:
			if claim.DecidedAt.IsZero() || claim.DecidedBy == "" {
				return fmt.Errorf("approved claim %s is missing decision metadata", claim.ID)
			}
			if claim.ReservedUntil.IsZero() {
				return fmt.Errorf("approved claim %s is missing reserved_until", claim.ID)
			}
		case ClaimRejected, ClaimExpired, ClaimCancelled:
		default:
			return fmt.Errorf("claim %s has unsupported status %q", claim.ID, claim.Status)
		}
		for _, ns := range state.Namespaces {
			if ns.ClaimID == claim.ID && claim.Status != ClaimApproved {
				return fmt.Errorf("namespace %s references non-approved claim %s", ns.Name, claim.ID)
			}
		}
		seenClaims[claim.ID] = struct{}{}
	}

	if err := verifyAuditChain(state.Audit); err != nil {
		return fmt.Errorf("audit chain: %w", err)
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func nowUTC() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}
