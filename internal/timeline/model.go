// Package timeline implements the merged file access timeline: ingestion,
// stable deduplication, tombstone-based deletion and filtering.
package timeline

import (
	"errors"
	"strings"
	"time"
)

// Action is a lifecycle or access event recorded for a file.
type Action string

const (
	ActionCreate   Action = "create"
	ActionGrant    Action = "grant"
	ActionPreview  Action = "preview"
	ActionDownload Action = "download"
	ActionRevoke   Action = "revoke"
	ActionMove     Action = "move"
	ActionUpdate   Action = "update"
)

// Actions lists every action understood by the timeline.
var Actions = []Action{
	ActionCreate,
	ActionGrant,
	ActionPreview,
	ActionDownload,
	ActionRevoke,
	ActionMove,
	ActionUpdate,
}

// ParseAction validates a raw action string, case-insensitively.
func ParseAction(raw string) (Action, bool) {
	want := Action(strings.ToLower(strings.TrimSpace(raw)))
	for _, action := range Actions {
		if action == want {
			return action, true
		}
	}
	return "", false
}

// ErrNotFound is returned when an event or file does not exist.
var ErrNotFound = errors.New("timeline: not found")

// ErrDeleted is returned when an event has been tombstoned.
var ErrDeleted = errors.New("timeline: event deleted")

// ErrInvalid is returned for malformed ingestion input.
var ErrInvalid = errors.New("timeline: invalid event")

// Event is a single timeline entry as exposed through the API and UI.
type Event struct {
	// DedupKey is the stable identity of an event. The same key always maps
	// to the same event, even when a report is delivered more than once.
	DedupKey string `json:"dedup_key"`
	FileID   string `json:"file_id"`
	// Seq is the global ingestion order, used for stable sorting.
	Seq        int64     `json:"seq"`
	Action     Action    `json:"action"`
	ActorID    string    `json:"actor_id"`
	OccurredAt time.Time `json:"occurred_at"`
	// VersionID is the file version current when the event happened. Events
	// can be grouped and jumped to by this value on the detail page.
	VersionID string `json:"version_id"`
	// Details carries action-specific data (grantee, paths, client ids ...).
	Details map[string]string `json:"details,omitempty"`
}

// IngestInput is the payload accepted when reporting an event.
type IngestInput struct {
	// ClientEventID is an upstream idempotency token. It is folded into the
	// computed dedup key so retries with the same token collapse together.
	ClientEventID string
	FileID        string
	Action        Action
	ActorID       string
	OccurredAt    time.Time
	VersionID     string
	Details       map[string]string
}

// Filter constrains a timeline query. Zero values mean "no constraint".
type Filter struct {
	FileID    string
	User      string
	Action    Action
	VersionID string
	From      time.Time
	To        time.Time
}

// FileInfo is the per-file summary derived from its timeline.
type FileInfo struct {
	FileID      string    `json:"file_id"`
	Name        string    `json:"name"`
	CurrentPath string    `json:"current_path"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LatestSeq   int64     `json:"latest_seq"`
	Versions    []string  `json:"versions"`
	EventCount  int       `json:"event_count"`
	DeletedKeys []string  `json:"deleted_keys"`
}

// Page is a filtered, ordered slice of events with totals.
type Page struct {
	Events    []Event `json:"events"`
	Total     int     `json:"total"`
	Filtered  int     `json:"filtered"`
	Truncated bool    `json:"truncated"`
	Limit     int     `json:"limit"`
}
