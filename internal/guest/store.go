package guest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const stateVersion = 1

// Store persists invitations and guest sessions in one JSON document.
type Store struct {
	mu    sync.Mutex
	path  string
	state diskState
}

func OpenStore(path string) (*Store, error) {
	store := &Store{
		path: path,
		state: diskState{
			Version:     stateVersion,
			Invitations: make(map[string]*Invitation),
			Sessions:    make(map[string]*Session),
		},
	}
	if path == "" {
		return store, nil
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := store.saveLocked(); err != nil {
			return nil, err
		}
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if store.state.Version != stateVersion {
		return nil, fmt.Errorf("unsupported state version %d", store.state.Version)
	}
	if store.state.Invitations == nil {
		store.state.Invitations = make(map[string]*Invitation)
	}
	if store.state.Sessions == nil {
		store.state.Sessions = make(map[string]*Session)
	}
	return store, nil
}

func (s *Store) createInvitation(invitation Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Invitations[invitation.ID]; exists {
		return fmt.Errorf("invitation id collision")
	}
	s.state.Invitations[invitation.ID] = &invitation
	return s.saveLocked()
}

func (s *Store) invitation(id string) (Invitation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.state.Invitations[id]
	if !ok {
		return Invitation{}, false
	}
	return *invitation, true
}

func (s *Store) invitationsFor(inviter string) []Invitation {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Invitation, 0, len(s.state.Invitations))
	for _, invitation := range s.state.Invitations {
		if invitation.Inviter == inviter {
			result = append(result, *invitation)
		}
	}
	return result
}

func (s *Store) addSession(session Session, joinedAt time.Time, setJoined bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.state.Invitations[session.InvitationID]
	if !ok {
		return ErrInvitationInvalid
	}
	if setJoined && invitation.JoinedAt == nil {
		joined := joinedAt
		invitation.JoinedAt = &joined
	}
	s.state.Sessions[session.ID] = &session
	return s.saveLocked()
}

func (s *Store) session(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.state.Sessions[id]
	if !ok {
		return Session{}, false
	}
	return *session, true
}

func (s *Store) revokeInvitation(inviter, id string, now time.Time) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.state.Invitations[id]
	if !ok || invitation.Inviter != inviter {
		return Invitation{}, ErrInvitationNotFound
	}
	if invitation.RevokedAt == nil {
		revoked := now
		invitation.RevokedAt = &revoked
		if err := s.saveLocked(); err != nil {
			return Invitation{}, err
		}
	}
	return *invitation, nil
}

func (s *Store) updateInvitationDirectory(id, directory string, dev, ino uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.state.Invitations[id]
	if !ok {
		return ErrInvitationInvalid
	}
	if invitation.Directory == directory && invitation.DirectoryDev == dev && invitation.DirectoryIno == ino {
		return nil
	}
	invitation.Directory = directory
	invitation.DirectoryDev = dev
	invitation.DirectoryIno = ino
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".guestshare-state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("set state permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}
