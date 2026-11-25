package cleanup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrNotFound      = errors.New("cleanup resource not found")
	ErrStalePreview  = errors.New("preview is stale; create a new preview")
	ErrInvalidFilter = errors.New("invalid item filter")
)

type Config struct {
	StorePath   string
	ManifestDir string
	FilesRoot   string
	Now         func() time.Time
	NewID       func() string
}

// Service serializes preview and execution operations in one process.
type Service struct {
	mu          sync.Mutex
	store       *Store
	db          *Database
	classifier  Classifier
	manifestDir string
	now         func() time.Time
	newID       func() string
	applyHook   func(run *CleanupRun, item *ManifestItem) error
}

func NewService(config Config) (*Service, error) {
	store, db, err := OpenStore(config.StorePath)
	if err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.NewID == nil {
		config.NewID = func() string { return mustRandomID() }
	}
	if config.ManifestDir != "" {
		if err := os.MkdirAll(config.ManifestDir, 0o755); err != nil {
			return nil, fmt.Errorf("create manifest directory: %w", err)
		}
	}
	return &Service{
		store:       store,
		db:          db,
		classifier:  Classifier{FilesRoot: config.FilesRoot},
		manifestDir: config.ManifestDir,
		now:         config.Now,
		newID:       config.NewID,
	}, nil
}

func (s *Service) CreatePreview() (Preview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	items := s.classifier.ClassifyAll(s.db)
	preview := Preview{
		ID:            s.uniqueIDLocked(),
		StateRevision: s.db.Revision,
		CreatedAt:     s.now(),
		Items:         items,
		Summary:       summarizePreview(items),
	}
	s.db.Previews[preview.ID] = preview
	if err := s.store.Save(s.db); err != nil {
		delete(s.db.Previews, preview.ID)
		return Preview{}, fmt.Errorf("save preview: %w", err)
	}
	return clonePreview(preview), nil
}

func (s *Service) GetPreview(id string) (Preview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	preview, ok := s.db.Previews[id]
	if !ok {
		return Preview{}, ErrNotFound
	}
	return clonePreview(preview), nil
}

func (s *Service) GetRun(id string) (CleanupRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.db.Runs[id]
	if !ok {
		return CleanupRun{}, ErrNotFound
	}
	return cloneRun(run), nil
}

func (s *Service) Snapshot() (*Database, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(s.db)
	if err != nil {
		return nil, err
	}
	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}
	return &db, nil
}

// SetApplyHook installs a deterministic fault hook for tests. Returning an
// error marks that item failed without touching the permission table.
func (s *Service) SetApplyHook(hook func(run *CleanupRun, item *ManifestItem) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyHook = hook
}

func (s *Service) uniqueIDLocked() string {
	for {
		base := s.newID()
		if base == "" {
			continue
		}
		for suffix := 1; ; suffix++ {
			id := base
			if suffix > 1 {
				id = fmt.Sprintf("%s-%d", base, suffix)
			}
			if !s.idUsedLocked(id) {
				return id
			}
		}
	}
}

func (s *Service) uniqueRunIDLocked() string {
	for {
		base := s.newID()
		if base == "" {
			continue
		}
		for suffix := 1; ; suffix++ {
			id := base
			if suffix > 1 {
				id = fmt.Sprintf("%s-%d", base, suffix)
			}
			if !s.idUsedLocked(id) {
				return id
			}
		}
	}
}

func (s *Service) idUsedLocked(id string) bool {
	if _, used := s.db.Previews[id]; used {
		return true
	}
	_, used := s.db.Runs[id]
	return used
}

func (s *Service) saveManifestLocked(run *CleanupRun) error {
	if s.manifestDir == "" {
		return nil
	}
	if run.ManifestPath == "" {
		run.ManifestPath = filepath.Join(s.manifestDir, run.ID+".json")
	}
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	data = append(data, '\n')
	if err := writeFileAtomic(run.ManifestPath, data); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func (s *Service) persistRunLocked(run *CleanupRun) error {
	run.UpdatedAt = s.now()
	if s.manifestDir != "" && run.ManifestPath == "" {
		run.ManifestPath = filepath.Join(s.manifestDir, run.ID+".json")
	}
	s.db.Runs[run.ID] = *run
	if err := s.store.Save(s.db); err != nil {
		return fmt.Errorf("save run: %w", err)
	}
	if err := s.saveManifestLocked(run); err != nil {
		return err
	}
	s.db.Runs[run.ID] = *run
	return nil
}

func clonePreview(preview Preview) Preview {
	copy := preview
	copy.Items = append([]PreviewItem(nil), preview.Items...)
	copy.Summary.ByCategory = make(map[Category]int, len(preview.Summary.ByCategory))
	for category, count := range preview.Summary.ByCategory {
		copy.Summary.ByCategory[category] = count
	}
	return copy
}

func cloneRun(run CleanupRun) CleanupRun {
	data, err := json.Marshal(run)
	if err != nil {
		return run
	}
	var copy CleanupRun
	if err := json.Unmarshal(data, &copy); err != nil {
		return run
	}
	return copy
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".manifest-*.json")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func mustRandomID() string {
	var buffer [16]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		panic(fmt.Sprintf("generate cleanup id: %v", err))
	}
	return hex.EncodeToString(buffer[:])
}
