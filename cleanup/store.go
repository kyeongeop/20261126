package cleanup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Store persists a whole JSON dataset using an atomic rename.
type Store struct {
	path string
}

func OpenStore(path string) (*Store, *Database, error) {
	store := &Store{path: path}
	db, err := store.Load()
	if err != nil {
		return nil, nil, err
	}
	return store, db, nil
}

func (s *Store) Load() (*Database, error) {
	if s.path == "" {
		return newDatabase(), nil
	}
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return newDatabase(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("open dataset: %w", err)
	}
	defer file.Close()

	var db Database
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&db); err != nil {
		return nil, fmt.Errorf("decode dataset: %w", err)
	}
	if err := ensureTrailingEOF(decoder); err != nil {
		return nil, err
	}
	normalizeDatabase(&db)
	if err := validateDatabase(&db); err != nil {
		return nil, err
	}
	return &db, nil
}

func (s *Store) Save(db *Database) error {
	if s.path == "" {
		return nil
	}
	if db == nil {
		return errors.New("save nil dataset")
	}
	normalizeDatabase(db)
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dataset directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".cleanup-*.json")
	if err != nil {
		return fmt.Errorf("create temporary dataset: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(db); err != nil {
		temp.Close()
		return fmt.Errorf("encode dataset: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync dataset: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close dataset: %w", err)
	}
	if err := os.Rename(tempName, s.path); err != nil {
		return fmt.Errorf("replace dataset: %w", err)
	}
	return nil
}

func newDatabase() *Database {
	db := &Database{Version: 1}
	normalizeDatabase(db)
	return db
}

func normalizeDatabase(db *Database) {
	if db.Version == 0 {
		db.Version = 1
	}
	if db.Users == nil {
		db.Users = []User{}
	}
	if db.Resources == nil {
		db.Resources = []Resource{}
	}
	if db.Permissions == nil {
		db.Permissions = []Permission{}
	}
	if db.Previews == nil {
		db.Previews = make(map[string]Preview)
	}
	if db.Runs == nil {
		db.Runs = make(map[string]CleanupRun)
	}
}

func ensureTrailingEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("dataset contains multiple JSON values")
		}
		return fmt.Errorf("decode dataset trailing value: %w", err)
	}
	return nil
}
