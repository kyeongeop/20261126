package timeline

import (
	"fmt"
	"strings"
	"time"
)

// IngestResult reports what happened during an Ingest call.
type IngestResult struct {
	Event      Event
	Duplicate  bool // an identical report was already ingested
	Suppressed bool // the key is tombstoned; the re-report is discarded
}

// validate normalizes and checks an ingestion payload.
func validate(in *IngestInput) error {
	in.FileID = strings.TrimSpace(in.FileID)
	in.ActorID = strings.TrimSpace(in.ActorID)
	in.ClientEventID = strings.TrimSpace(in.ClientEventID)
	in.VersionID = strings.TrimSpace(in.VersionID)
	if in.FileID == "" {
		return fmt.Errorf("%w: file_id is required", ErrInvalid)
	}
	if _, ok := ParseAction(string(in.Action)); !ok {
		return fmt.Errorf("%w: unknown action %q", ErrInvalid, in.Action)
	}
	if in.ActorID == "" {
		return fmt.Errorf("%w: actor_id is required", ErrInvalid)
	}
	if in.OccurredAt.IsZero() {
		in.OccurredAt = time.Now().UTC()
	}
	in.OccurredAt = in.OccurredAt.UTC()

	clean := make(map[string]string, len(in.Details))
	for key, value := range in.Details {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		clean[key] = strings.TrimSpace(value)
	}
	in.Details = clean
	return nil
}

// deriveVersion fills in a version id when the caller did not provide one.
// Create events start at v1; other events attach to the latest known
// version of the file.
func (s *Store) deriveVersion(in *IngestInput) {
	if in.VersionID != "" {
		return
	}
	if in.Action == ActionCreate {
		in.VersionID = defaultVersion
		return
	}
	if state, ok := s.files[in.FileID]; ok && len(state.info.Versions) > 0 {
		in.VersionID = state.info.Versions[len(state.info.Versions)-1]
		return
	}
	in.VersionID = defaultVersion
}

// Ingest records one event. It is idempotent: an event with an already
// known dedup key is not stored again, even if the previous copy was
// deleted (tombstones suppress re-reports of the same logical event).
func (s *Store) Ingest(in IngestInput) (IngestResult, error) {
	if err := validate(&in); err != nil {
		return IngestResult{}, err
	}
	key := DedupKey(in)

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.events[key]; ok {
		return IngestResult{Event: *existing, Duplicate: true}, nil
	}
	if _, deleted := s.tomb[key]; deleted {
		return IngestResult{
			Event:      Event{DedupKey: key, FileID: in.FileID, Action: in.Action},
			Suppressed: true,
		}, nil
	}

	s.deriveVersion(&in)
	s.seq++
	ev := &Event{
		DedupKey:   key,
		FileID:     in.FileID,
		Seq:        s.seq,
		Action:     in.Action,
		ActorID:    in.ActorID,
		OccurredAt: in.OccurredAt,
		VersionID:  in.VersionID,
		Details:    in.Details,
	}
	if err := s.appendLocked(record{Type: "event", Seq: s.seq, Event: ev}); err != nil {
		s.seq--
		return IngestResult{}, err
	}
	s.indexEvent(ev)
	return IngestResult{Event: *ev}, nil
}

// Delete tombstones an event. The tombstone is appended to the log and the
// dedup key remains reserved, so later duplicate reports stay suppressed.
func (s *Store) Delete(dedupKey string) error {
	dedupKey = strings.TrimSpace(dedupKey)
	if dedupKey == "" {
		return fmt.Errorf("%w: dedup_key is required", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ev, ok := s.events[dedupKey]
	if !ok {
		if _, deleted := s.tomb[dedupKey]; deleted {
			return ErrDeleted
		}
		return ErrNotFound
	}
	now := time.Now().UTC()
	if err := s.appendLocked(record{
		Type:      "tombstone",
		Seq:       s.seq,
		DedupKey:  dedupKey,
		DeletedAt: now,
	}); err != nil {
		return err
	}
	delete(s.events, dedupKey)
	s.tomb[dedupKey] = now
	if state, ok := s.files[ev.FileID]; ok {
		state.info.EventCount--
		state.info.DeletedKeys = append(state.info.DeletedKeys, dedupKey)
	}
	return nil
}

// IsDeleted reports whether the key is currently tombstoned.
func (s *Store) IsDeleted(dedupKey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.tomb[strings.TrimSpace(dedupKey)]
	return ok
}
