package timeline

import (
	"fmt"
	"sort"
	"strings"
)

// userDetailKeys names detail entries that refer to a user other than the
// actor (for example the grantee of an authorization event).
var userDetailKeys = map[string]bool{
	"grantee": true, "grantee_id": true,
	"revokee": true, "revokee_id": true,
	"user": true, "user_id": true,
	"target": true, "target_id": true,
	"subject": true, "subject_id": true,
	"member": true, "member_id": true,
}

func matchesUser(ev *Event, user string) bool {
	if ev.ActorID == user {
		return true
	}
	for key, value := range ev.Details {
		if userDetailKeys[key] && value == user {
			return true
		}
	}
	return false
}

func matches(ev *Event, f Filter) bool {
	if f.FileID != "" && ev.FileID != f.FileID {
		return false
	}
	if f.User != "" && !matchesUser(ev, f.User) {
		return false
	}
	if f.Action != "" && ev.Action != f.Action {
		return false
	}
	if f.VersionID != "" && ev.VersionID != f.VersionID {
		return false
	}
	if !f.From.IsZero() && ev.OccurredAt.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && ev.OccurredAt.After(f.To) {
		return false
	}
	return true
}

func cloneEvent(ev *Event) Event {
	copy := *ev
	if len(ev.Details) > 0 {
		copy.Details = make(map[string]string, len(ev.Details))
		for key, value := range ev.Details {
			copy.Details[key] = value
		}
	}
	return copy
}

// List returns events matching the filter, ordered by occurrence time and
// ingestion sequence for a stable order. Limit <= 0 returns every match.
func (s *Store) List(f Filter, limit int) (Page, error) {
	if strings.TrimSpace(f.FileID) == "" {
		return Page{}, fmt.Errorf("%w: file_id filter is required", ErrInvalid)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	matched := make([]Event, 0)
	total := 0
	state := s.files[f.FileID]
	if state != nil {
		total = state.info.EventCount
	}
	for _, ev := range s.events {
		if !matches(ev, f) {
			continue
		}
		matched = append(matched, cloneEvent(ev))
	}
	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].OccurredAt.Equal(matched[j].OccurredAt) {
			return matched[i].OccurredAt.Before(matched[j].OccurredAt)
		}
		return matched[i].Seq < matched[j].Seq
	})

	page := Page{Events: matched, Total: total, Filtered: len(matched)}
	if limit > 0 && len(matched) > limit {
		page.Events = matched[:limit]
		page.Truncated = true
		page.Limit = limit
	}
	return page, nil
}

// Get returns a single live event by dedup key.
func (s *Store) Get(dedupKey string) (Event, error) {
	dedupKey = strings.TrimSpace(dedupKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ev, ok := s.events[dedupKey]; ok {
		return cloneEvent(ev), nil
	}
	if _, ok := s.tomb[dedupKey]; ok {
		return Event{}, ErrDeleted
	}
	return Event{}, ErrNotFound
}

func cloneFileInfo(info FileInfo) FileInfo {
	copy := info
	copy.Versions = append([]string(nil), info.Versions...)
	copy.DeletedKeys = append([]string(nil), info.DeletedKeys...)
	return copy
}

// GetFile returns the aggregated summary of one file.
func (s *Store) GetFile(fileID string) (FileInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.files[strings.TrimSpace(fileID)]
	if !ok {
		return FileInfo{}, ErrNotFound
	}
	return cloneFileInfo(state.info), nil
}

// ListFiles returns summaries of every known file, ordered by file id.
func (s *Store) ListFiles() []FileInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FileInfo, 0, len(s.files))
	for _, id := range s.sortedFiles() {
		out = append(out, cloneFileInfo(s.files[id].info))
	}
	return out
}

// DeletedKeys returns the tombstoned dedup keys of a file.
func (s *Store) DeletedKeys(fileID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.files[fileID]
	if !ok {
		return nil
	}
	return append([]string(nil), state.info.DeletedKeys...)
}
