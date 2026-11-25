package timeline

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const defaultVersion = "v1"

// record is the on-disk envelope of the append-only JSONL log.
type record struct {
	Type      string    `json:"type"` // "event" or "tombstone"
	Seq       int64     `json:"seq"`
	Event     *Event    `json:"event,omitempty"`
	DedupKey  string    `json:"dedup_key,omitempty"`
	DeletedAt time.Time `json:"deleted_at,omitempty"`
}

type fileState struct {
	info      FileInfo
	versionOK map[string]bool
}

// Store is the file access timeline store. It persists events to an
// append-only JSONL file and keeps query indexes in memory; no external
// database is involved.
type Store struct {
	path string
	mu   sync.RWMutex

	log    *os.File
	seq    int64
	events map[string]*Event
	tomb   map[string]time.Time
	files  map[string]*fileState
}

// Open opens (or creates) the store at dir/timeline.jsonl and replays the
// log so tombstones and dedup keys survive restarts.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("timeline: create data dir: %w", err)
	}
	path := filepath.Join(dir, "timeline.jsonl")
	log, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("timeline: open log: %w", err)
	}

	s := &Store{
		path:   path,
		log:    log,
		events: make(map[string]*Event),
		tomb:   make(map[string]time.Time),
		files:  make(map[string]*fileState),
	}
	if err := s.replay(); err != nil {
		_ = log.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying log file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.log.Close()
}

func (s *Store) replay() error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return fmt.Errorf("timeline: corrupt log record: %w", err)
		}
		if rec.Seq > s.seq {
			s.seq = rec.Seq
		}
		switch rec.Type {
		case "event":
			if rec.Event == nil || rec.Event.DedupKey == "" {
				return fmt.Errorf("timeline: corrupt event record")
			}
			s.indexEvent(rec.Event)
		case "tombstone":
			fileID := ""
			if ev := s.events[rec.DedupKey]; ev != nil {
				fileID = ev.FileID
			}
			delete(s.events, rec.DedupKey)
			s.tomb[rec.DedupKey] = rec.DeletedAt
			if state, ok := s.files[fileID]; ok {
				state.info.EventCount--
				state.info.DeletedKeys = append(state.info.DeletedKeys, rec.DedupKey)
			}
		default:
			return fmt.Errorf("timeline: unknown record type %q", rec.Type)
		}
	}
	return scanner.Err()
}

func (s *Store) indexEvent(ev *Event) {
	s.events[ev.DedupKey] = ev
	state := s.files[ev.FileID]
	if state == nil {
		state = &fileState{info: FileInfo{FileID: ev.FileID}, versionOK: map[string]bool{}}
		s.files[ev.FileID] = state
	}
	if !state.versionOK[ev.VersionID] {
		state.versionOK[ev.VersionID] = true
		state.info.Versions = append(state.info.Versions, ev.VersionID)
	}
	state.info.EventCount++
	if state.info.CreatedAt.IsZero() || ev.OccurredAt.Before(state.info.CreatedAt) {
		state.info.CreatedAt = ev.OccurredAt
	}
	if ev.OccurredAt.After(state.info.UpdatedAt) {
		state.info.UpdatedAt = ev.OccurredAt
		state.info.LatestSeq = ev.Seq
	}
	if name := ev.Details["file_name"]; name != "" {
		state.info.Name = name
	}
	if path := ev.Details["path"]; path != "" && ev.Action == ActionCreate {
		state.info.CurrentPath = path
	}
	if to := ev.Details["to_path"]; to != "" && ev.Action == ActionMove {
		state.info.CurrentPath = to
	}
}

func (s *Store) appendLocked(rec record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := s.log.Write(data); err != nil {
		return fmt.Errorf("timeline: append log: %w", err)
	}
	return s.log.Sync()
}

// sortedFiles returns file ids in lexical order for deterministic output.
func (s *Store) sortedFiles() []string {
	ids := make([]string, 0, len(s.files))
	for id := range s.files {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
