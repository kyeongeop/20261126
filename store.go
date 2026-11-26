package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const stateFileName = "state.json"

// Store 是单个 Go 进程内的全部状态：内存数据 + JSON 原子落盘 + 内容寻址归档目录。
type Store struct {
	mu         sync.Mutex
	dir        string
	objectsDir string
	statePath  string
	cooldown   time.Duration
	now        func() time.Time

	State *State
}

// State 是序列化到 state.json 的根对象。
type State struct {
	SchemaVersion int                 `json:"schema_version"`
	Packages      map[string]*Package `json:"packages"`
	Downloads     []DownloadRecord    `json:"downloads"`
	Builds        []BuildRecord       `json:"builds"`
	References    []Reference         `json:"references"`
	Deletions     []*DeletionRequest  `json:"deletion_requests"`
	Counters      map[string]int      `json:"counters"`
}

// NewStore 打开（必要时初始化并写入演示数据）一个仓库存储。
func NewStore(dir string, cooldown time.Duration) (*Store, error) {
	if dir == "" {
		dir = "data"
	}
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{
		dir:        dir,
		objectsDir: filepath.Join(dir, "objects"),
		statePath:  filepath.Join(dir, stateFileName),
		cooldown:   cooldown,
		now:        time.Now,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read state: %w", err)
		}
		s.State = freshState()
		return s.persistLocked()
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("parse %s: %w", stateFileName, err)
	}
	if state.Packages == nil {
		state.Packages = map[string]*Package{}
	}
	if state.Counters == nil {
		state.Counters = map[string]int{}
	}
	if state.SchemaVersion == 0 {
		state.SchemaVersion = 1
	}
	s.State = &state
	return nil
}

func freshState() *State {
	return &State{
		SchemaVersion: 1,
		Packages:      map[string]*Package{},
		Downloads:     []DownloadRecord{},
		Builds:        []BuildRecord{},
		References:    []Reference{},
		Deletions:     []*DeletionRequest{},
		Counters:      map[string]int{},
	}
}

// persistLocked 以“临时文件 + fsync + rename”原子替换状态文件。调用方必须持有锁。
func (s *Store) persistLocked() error {
	raw, err := json.MarshalIndent(s.State, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmpName, s.statePath); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

// save 是需要改状态的写操作的统一入口。
func (s *Store) save(mutate func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := mutate(); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Store) nextNumber(key string) int {
	s.State.Counters[key]++
	return s.State.Counters[key]
}

func (s *Store) newID(prefix, key string) (string, int) {
	n := s.nextNumber(key)
	return fmt.Sprintf("%s-%d", prefix, n), n
}

// SetClock 覆盖时间源（主要用于测试）。
func (s *Store) SetClock(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fn != nil {
		s.now = fn
	}
}

// Cooldown 返回当前配置的冷静期时长。
func (s *Store) Cooldown() time.Duration {
	return s.cooldown
}
