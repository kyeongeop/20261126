// Package token implements one-time preview tokens bound to a file, version,
// user, purpose and expiry time.
//
// A token is an HMAC-SHA256 signed, JSON-encoded Claims value
// ("payload.signature"). Signature verification proves the claims were issued
// by the server; a server-side consumption ledger (see Store) enforces that a
// token is used at most once even when requests race.
//
// Thumbnail batches of one page are supported in two replay-safe ways:
//
//  1. IssueBatch mints distinct one-time tokens, one per thumbnail. The page
//     fires all of them concurrently; every token is new, so none is a replay.
//  2. A one-time "page" token is exchanged once via OpenSession for a short
//     lived batch grant (KindBatch) that carries an item allow list. Each
//     distinct item may be consumed once; a repeated item is a replay.
package token

import (
	"errors"
	"time"
)

// Token kinds.
const (
	// KindOnce is a strict single-use token (default).
	KindOnce = "once"
	// KindBatch is a short-lived grant that permits one consumption per
	// allow-listed item.
	KindBatch = "batch"
)

// Standard purposes. Tokens are bound to exactly one purpose.
const (
	PurposePreview   = "preview"
	PurposeThumbnail = "thumbnail"
	PurposeDownload  = "download"
	PurposePage      = "page"
)

// Sentinel errors returned by Manager operations. Callers should use
// errors.Is to classify them.
var (
	// ErrInvalidToken covers malformed or unverifiable tokens.
	ErrInvalidToken = errors.New("previewtoken: invalid token")
	// ErrExpired means the token's expiry time has passed.
	ErrExpired = errors.New("previewtoken: token expired")
	// ErrReplay means the one-time token (or batch item) was already consumed.
	ErrReplay = errors.New("previewtoken: token has already been used")
	// ErrBinding means request context (file/version/user/purpose/item) does
	// not match the claims embedded in the token.
	ErrBinding = errors.New("previewtoken: request context does not match token binding")
	// ErrUnknownToken means the signature is valid but no local record exists.
	ErrUnknownToken = errors.New("previewtoken: token record not found")
	// ErrItemRequired means a batch grant was used without an item selector.
	ErrItemRequired = errors.New("previewtoken: item is required for a batch grant")
	// ErrItemNotAllowed means the requested item is not in the batch allow list.
	ErrItemNotAllowed = errors.New("previewtoken: item is not part of this batch")
	// ErrInvalidRequest covers missing or malformed issuance parameters.
	ErrInvalidRequest = errors.New("previewtoken: invalid token request")
)

// Claims is the signed payload of a preview token.
type Claims struct {
	// JTI is the unique token identifier used in the consumption ledger.
	JTI string `json:"jti"`
	// Kind is KindOnce (empty is treated as KindOnce) or KindBatch.
	Kind string `json:"kind,omitempty"`

	// Binding fields: the token is locked to this exact context.
	File    string `json:"file"`
	Version string `json:"version"`
	User    string `json:"user"`
	Purpose string `json:"purpose"`

	// Item labels a single thumbnail within a batch.
	Item string `json:"item,omitempty"`
	// Items is the allow list carried by KindBatch grants and page tokens.
	Items []string `json:"items,omitempty"`
	// BatchID groups all tokens minted for the same page render.
	BatchID string `json:"batch_id,omitempty"`
	// MaxUses bounds consumptions of a KindBatch grant.
	MaxUses int `json:"max_uses,omitempty"`

	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

// Binding is the request-supplied context checked against Claims. Empty
// fields are not checked, so callers may verify only the dimensions the
// request actually asserts.
type Binding struct {
	File    string
	Version string
	User    string
	Purpose string
	Item    string
}

// Match reports whether b is compatible with c.
func (b Binding) Match(c Claims) error {
	if b.File != "" && b.File != c.File {
		return errors.Join(ErrBinding, errors.New("file mismatch"))
	}
	if b.Version != "" && b.Version != c.Version {
		return errors.Join(ErrBinding, errors.New("version mismatch"))
	}
	if b.User != "" && b.User != c.User {
		return errors.Join(ErrBinding, errors.New("user mismatch"))
	}
	if b.Purpose != "" && b.Purpose != c.Purpose {
		return errors.Join(ErrBinding, errors.New("purpose mismatch"))
	}
	if b.Item != "" && c.Item != "" && b.Item != c.Item {
		return errors.Join(ErrBinding, errors.New("item mismatch"))
	}
	return nil
}

// IssueRequest configures a newly minted one-time token.
type IssueRequest struct {
	File      string
	Version   string
	User      string
	Purpose   string
	TTL       time.Duration
	ExpiresAt time.Time
	// Items is attached to PurposePage tokens as the thumbnail allow list.
	Items []string
	// Item labels the single resource this token protects.
	Item string
	// BatchID groups batch-issued tokens.
	BatchID string
}

// BatchRequest asks for one distinct one-time token per thumbnail item.
type BatchRequest struct {
	File    string
	Version string
	User    string
	Purpose string
	TTL     time.Duration
	Items   []string
}

// Batch is the result of IssueBatch.
type Batch struct {
	BatchID   string
	Items     []string
	Tokens    []string
	Claims    []Claims
	ExpiresAt time.Time
}
