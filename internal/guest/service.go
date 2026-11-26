package guest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type Config struct {
	Root     string
	DataFile string
	Now      func() time.Time
}

// Service owns invitation lifecycle and resolves the currently authorized
// directory for every guest request.
type Service struct {
	shareRoot string
	store     *Store
	now       func() time.Time
}

func NewService(config Config) (*Service, error) {
	if strings.TrimSpace(config.Root) == "" {
		return nil, fmt.Errorf("share root is required")
	}
	root, err := filepath.Abs(config.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve share root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve share root symlinks: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat share root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("share root is not a directory")
	}
	store, err := OpenStore(config.DataFile)
	if err != nil {
		return nil, err
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Service{shareRoot: root, store: store, now: now}, nil
}

func (s *Service) CreateInvitation(params CreateInvitationParams) (CreateInvitationResult, error) {
	params.Inviter = strings.TrimSpace(params.Inviter)
	params.DisplayName = strings.TrimSpace(params.DisplayName)
	if params.Inviter == "" {
		return CreateInvitationResult{}, newError("invalid_request", "inviter is required", 400)
	}
	if params.DisplayName == "" || utf8.RuneCountInString(params.DisplayName) > 80 {
		return CreateInvitationResult{}, newError("invalid_request", "display_name must contain 1 to 80 characters", 400)
	}
	if strings.ContainsRune(params.DisplayName, '\x00') {
		return CreateInvitationResult{}, newError("invalid_request", "display_name contains an invalid character", 400)
	}
	if len(params.Passcode) > 128 {
		return CreateInvitationResult{}, newError("invalid_request", "passcode must be at most 128 bytes", 400)
	}

	now := s.now().UTC()
	if !params.ExpiresAt.After(now) {
		return CreateInvitationResult{}, newError("invalid_request", "expires_at must be in the future", 400)
	}
	directory, dev, ino, err := s.resolveGrant(params.Directory)
	if err != nil {
		return CreateInvitationResult{}, err
	}

	id, token, tokenHash, err := newCredential()
	if err != nil {
		return CreateInvitationResult{}, wrapError("internal_error", "could not create invitation", 500, err)
	}
	invitation := Invitation{
		ID:           id,
		DisplayName:  params.DisplayName,
		Inviter:      params.Inviter,
		Directory:    directory,
		DirectoryDev: dev,
		DirectoryIno: ino,
		TokenHash:    tokenHash,
		CreatedAt:    now,
		ExpiresAt:    params.ExpiresAt.UTC(),
	}
	if params.Passcode != "" {
		salt, err := randomSalt()
		if err != nil {
			return CreateInvitationResult{}, wrapError("internal_error", "could not create invitation", 500, err)
		}
		invitation.PasscodeSalt = salt
		invitation.PasscodeRounds = defaultPasscodeRounds
		invitation.PasscodeHash = hashPasscode(salt, params.Passcode, invitation.PasscodeRounds)
	}
	if err := s.store.createInvitation(invitation); err != nil {
		return CreateInvitationResult{}, wrapError("internal_error", "could not save invitation", 500, err)
	}
	return CreateInvitationResult{
		Invitation:      invitationView(invitation, now, true),
		InvitationToken: token,
	}, nil
}

func (s *Service) Join(rawToken, passcode string) (JoinResult, error) {
	invitationID, secret, ok := splitToken(rawToken)
	if !ok {
		return JoinResult{}, ErrInvitationInvalid
	}
	invitation, ok := s.store.invitation(invitationID)
	if !ok || !constantTimeEqual(hashString(secret), invitation.TokenHash) {
		return JoinResult{}, ErrInvitationInvalid
	}
	now := s.now().UTC()
	if err := validateInvitation(invitation, now); err != nil {
		return JoinResult{}, err
	}
	if invitation.PasscodeHash != "" {
		if passcode == "" {
			return JoinResult{}, ErrPasscodeRequired
		}
		if !constantTimeEqual(
			hashPasscode(invitation.PasscodeSalt, passcode, invitation.PasscodeRounds),
			invitation.PasscodeHash,
		) {
			return JoinResult{}, ErrPasscodeInvalid
		}
	}

	currentDirectory, err := s.syncDirectory(invitation)
	if err != nil {
		return JoinResult{}, err
	}
	invitation.Directory = currentDirectory

	sessionID, sessionToken, sessionHash, err := newCredential()
	if err != nil {
		return JoinResult{}, wrapError("internal_error", "could not create guest session", 500, err)
	}
	session := Session{
		ID:           sessionID,
		InvitationID: invitation.ID,
		TokenHash:    sessionHash,
		CreatedAt:    now,
		ExpiresAt:    invitation.ExpiresAt,
	}
	if err := s.store.addSession(session, now, true); err != nil {
		return JoinResult{}, wrapError("internal_error", "could not save guest session", 500, err)
	}
	return JoinResult{
		Guest: GuestView{
			DisplayName: invitation.DisplayName,
			Directory:   invitation.Directory,
			ExpiresAt:   invitation.ExpiresAt,
		},
		SessionToken: sessionToken,
	}, nil
}

func (s *Service) Authenticate(rawSession string) (GuestSession, error) {
	sessionID, secret, ok := splitToken(rawSession)
	if !ok {
		return GuestSession{}, ErrSessionInvalid
	}
	session, ok := s.store.session(sessionID)
	if !ok || !constantTimeEqual(hashString(secret), session.TokenHash) {
		return GuestSession{}, ErrSessionInvalid
	}
	now := s.now().UTC()
	invitation, ok := s.store.invitation(session.InvitationID)
	if !ok {
		return GuestSession{}, ErrSessionInvalid
	}
	if err := validateInvitation(invitation, now); err != nil {
		return GuestSession{}, err
	}
	if !now.Before(session.ExpiresAt) {
		return GuestSession{}, ErrSessionInvalid
	}
	currentDirectory, err := s.syncDirectory(invitation)
	if err != nil {
		return GuestSession{}, err
	}
	invitation.Directory = currentDirectory
	rootPath := filepath.Join(s.shareRoot, filepath.FromSlash(currentDirectory))
	return GuestSession{
		Invitation: invitationView(invitation, now, true),
		RootPath:   rootPath,
	}, nil
}

func (s *Service) ListInvitations(inviter string) []InvitationView {
	invitations := s.store.invitationsFor(inviter)
	now := s.now().UTC()
	views := make([]InvitationView, 0, len(invitations))
	for i := range invitations {
		available := false
		if validateInvitation(invitations[i], now) == nil {
			if current, err := s.syncDirectory(invitations[i]); err == nil {
				invitations[i].Directory = current
				available = true
			}
		}
		views = append(views, invitationView(invitations[i], now, available))
	}
	sort.Slice(views, func(i, j int) bool {
		return views[i].CreatedAt.After(views[j].CreatedAt)
	})
	return views
}

func (s *Service) RevokeInvitation(inviter, id string) (InvitationView, error) {
	now := s.now().UTC()
	invitation, err := s.store.revokeInvitation(inviter, id, now)
	if err != nil {
		if errors.Is(err, ErrInvitationNotFound) {
			return InvitationView{}, err
		}
		return InvitationView{}, wrapError("internal_error", "could not revoke invitation", 500, err)
	}
	return invitationView(invitation, now, false), nil
}

func validateInvitation(invitation Invitation, now time.Time) error {
	if invitation.RevokedAt != nil {
		return ErrInvitationRevoked
	}
	if !now.Before(invitation.ExpiresAt) {
		return ErrInvitationExpired
	}
	return nil
}

func invitationView(invitation Invitation, now time.Time, available bool) InvitationView {
	status := "active"
	if invitation.RevokedAt != nil {
		status = "revoked"
	} else if !now.Before(invitation.ExpiresAt) {
		status = "expired"
	}
	return InvitationView{
		ID:                 invitation.ID,
		DisplayName:        invitation.DisplayName,
		Inviter:            invitation.Inviter,
		Directory:          invitation.Directory,
		DirectoryAvailable: available,
		CreatedAt:          invitation.CreatedAt,
		ExpiresAt:          invitation.ExpiresAt,
		JoinedAt:           invitation.JoinedAt,
		RevokedAt:          invitation.RevokedAt,
		Status:             status,
	}
}
