package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"teamsync/internal/model"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrNameConflict = errors.New("a node with the same name already exists in this folder")
	ErrInvalidName  = errors.New("name must not be empty or contain '/'")
	ErrParentFolder = errors.New("parent must be a folder")
	ErrMoveRoot     = errors.New("the root folder cannot be moved")
	ErrMoveIntoSelf = errors.New("cannot move a folder into itself or one of its descendants")
	ErrInvalidKind  = errors.New("node kind must be folder or file")
	ErrUserNotFound = errors.New("user not found")
)

// Store is the JSON-backed application state. A single mutex guards every
// mutation; the process stays single-instance as required.
type Store struct {
	mu   sync.RWMutex
	data *model.StoreData
	file string
}

// NewStore loads state from dataDir, bootstrapping an empty tree on first run.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	file := filepath.Join(dataDir, "teamsync.json")
	data := &model.StoreData{
		NextID: 2,
		Users:  map[string]*model.User{},
		Nodes:  map[string]*model.Node{},
	}
	if raw, err := os.ReadFile(file); err == nil {
		if err := json.Unmarshal(raw, data); err != nil {
			return nil, fmt.Errorf("corrupt state file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	store := &Store{data: data, file: file}
	if data.RootID == "" {
		now := nowTS()
		root := &model.Node{
			ID:        "n1",
			Name:      "Root",
			Kind:      model.KindFolder,
			ParentID:  "",
			Path:      "/",
			Direct:    map[string]*model.ACE{},
			CreatedAt: now,
			UpdatedAt: now,
		}
		data.Nodes[root.ID] = root
		data.RootID = root.ID
		if err := store.persistLocked(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func nowTS() string { return time.Now().UTC().Format(time.RFC3339) }

func (s *Store) persistLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.file + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.file)
}

func (s *Store) nextID(prefix string) string {
	id := fmt.Sprintf("%s%d", prefix, s.data.NextID)
	s.data.NextID++
	return id
}

// RootID returns the fixed root folder ID.
func (s *Store) RootID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.RootID
}

// Node implements perm.Catalog.
func (s *Store) Node(id string) (*model.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.data.Nodes[id]
	return node, ok
}

// User looks up a user by ID.
func (s *Store) User(id string) (*model.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.data.Users[id]
	return user, ok
}

// Users lists all users sorted by name, then ID (duplicate names stay distinct).
func (s *Store) Users() []*model.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.User, 0, len(s.data.Users))
	for _, user := range s.data.Users {
		out = append(out, user)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Nodes lists all nodes in a stable order.
func (s *Store) Nodes() []*model.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Node, 0, len(s.data.Nodes))
	for _, node := range s.data.Nodes {
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// CreateUser adds a user. Names may repeat; only the generated ID is unique.
func (s *Store) CreateUser(name string) (*model.User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user := &model.User{ID: s.nextID("u"), Name: name}
	s.data.Users[user.ID] = user
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return user, nil
}

func validName(name string) bool {
	return name != "" && !strings.Contains(name, "/")
}

func (s *Store) siblingNamedLocked(parentID, name, excludeID string) bool {
	for _, node := range s.data.Nodes {
		if node.ParentID == parentID && node.Name == name && node.ID != excludeID {
			return true
		}
	}
	return false
}
