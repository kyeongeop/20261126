// Package store persists JSON-encoded application state in local files.
//
// All writes are atomic: data is written to a temporary file in the same
// directory and then renamed, so a crash can never leave a half-written
// state file. A mutex serializes writers within the process.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrNotFound is returned by Update when the file does not exist yet and the
// caller did not ask for initialization.
var ErrNotFound = errors.New("store: file not found")

// JSONFile is a small atomic JSON document backed by a single file.
// The zero value is not usable; use Open.
type JSONFile[T any] struct {
	path string
	mu   sync.Mutex
}

// Open prepares a JSONFile at path. Missing files are created lazily on the
// first Update that supplies an initial value.
func Open[T any](path string) (*JSONFile[T], error) {
	if filepath.Clean(path) == "." || path == "" {
		return nil, errors.New("store: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("store: create directory: %w", err)
	}
	return &JSONFile[T]{path: path}, nil
}

// View calls fn with a snapshot of the stored value. If the file does not
// exist, fn receives the zero value. fn must not retain the pointer.
func (f *JSONFile[T]) View(fn func(*T) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	value, err := f.loadLocked()
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		value = new(T)
	}
	return fn(value)
}

// Update applies fn to the stored value and persists the result. If the file
// does not exist, initial is used as the starting document. The mutation is
// only written when fn returns nil.
func (f *JSONFile[T]) Update(initial T, fn func(*T) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	value, err := f.loadLocked()
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		value = &initial
	}
	if err := fn(value); err != nil {
		return err
	}
	return f.persistLocked(value)
}

func (f *JSONFile[T]) loadLocked() (*T, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return new(T), ErrNotFound
		}
		return nil, fmt.Errorf("store: read %s: %w", f.path, err)
	}
	var value T
	if len(data) == 0 {
		return &value, nil
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("store: decode %s: %w", f.path, err)
	}
	return &value, nil
}

func (f *JSONFile[T]) persistLocked(value *T) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode %s: %w", f.path, err)
	}

	dir := filepath.Dir(f.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(f.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("store: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write %s: %w", f.path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: sync %s: %w", f.path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close %s: %w", f.path, err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		return fmt.Errorf("store: rename %s: %w", f.path, err)
	}
	return nil
}
