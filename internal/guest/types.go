package guest

import "time"

// Invitation is the persisted grant created by a team member. Secrets are
// stored only as hashes; the raw tokens are returned once to the inviter.
type Invitation struct {
	ID             string     `json:"id"`
	DisplayName    string     `json:"display_name"`
	Inviter        string     `json:"inviter"`
	Directory      string     `json:"directory"`
	DirectoryDev   uint64     `json:"directory_dev"`
	DirectoryIno   uint64     `json:"directory_ino"`
	PasscodeSalt   string     `json:"passcode_salt,omitempty"`
	PasscodeHash   string     `json:"passcode_hash,omitempty"`
	PasscodeRounds int        `json:"passcode_rounds,omitempty"`
	TokenHash      string     `json:"token_hash"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	JoinedAt       *time.Time `json:"joined_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

type Session struct {
	ID           string    `json:"id"`
	InvitationID string    `json:"invitation_id"`
	TokenHash    string    `json:"token_hash"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type diskState struct {
	Version     int                    `json:"version"`
	Invitations map[string]*Invitation `json:"invitations"`
	Sessions    map[string]*Session    `json:"sessions"`
}

type InvitationView struct {
	ID                 string     `json:"id"`
	DisplayName        string     `json:"display_name"`
	Inviter            string     `json:"inviter"`
	Directory          string     `json:"directory"`
	DirectoryAvailable bool       `json:"directory_available"`
	CreatedAt          time.Time  `json:"created_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	JoinedAt           *time.Time `json:"joined_at,omitempty"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
	Status             string     `json:"status"`
}

type GuestView struct {
	DisplayName string    `json:"display_name"`
	Directory   string    `json:"directory"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type EntryView struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Size       int64     `json:"size,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
}

type CreateInvitationParams struct {
	Inviter     string
	DisplayName string
	Passcode    string
	Directory   string
	ExpiresAt   time.Time
}

type CreateInvitationResult struct {
	Invitation      InvitationView
	InvitationToken string
}

type JoinResult struct {
	Guest        GuestView
	SessionToken string
}

type GuestSession struct {
	Invitation InvitationView
	RootPath   string
}
