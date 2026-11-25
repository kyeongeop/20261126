package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNothingToRevoke 表示筛选结果中没有处于 active 状态、可撤销的链接。
	ErrNothingToRevoke = errors.New("筛选条件下没有可撤销的有效分享链接")
	// ErrNotFound 表示请求的审计记录等实体不存在。
	ErrNotFound = errors.New("记录不存在")
)

// Store 用单个 JSON 文件保存分享与审计数据。
// 所有变更都在互斥锁内完成，并通过“临时文件 + rename”原子提交；
// 提交失败时用内存快照整体回滚，保证一次批量操作全成或全不成。
type Store struct {
	dir      string
	filePath string
	mu       sync.Mutex
	db       dbData
	now      func() time.Time
	// writeFileAtomic 可在测试中替换为失败实现，用于验证回滚。
	writeFileAtomic func(path string, data []byte) error
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("创建数据目录失败 %s: %w", dir, err)
	}
	s := &Store{
		dir:             dir,
		filePath:        filepath.Join(dir, "db.json"),
		now:             func() time.Time { return time.Now().UTC() },
		writeFileAtomic: atomicWriteJSON,
	}
	raw, err := os.ReadFile(s.filePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.db = seedDB()
		if err := s.persistLocked(s.db); err != nil {
			return nil, fmt.Errorf("初始化数据文件失败: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("读取数据文件失败: %w", err)
	default:
		if err := json.Unmarshal(raw, &s.db); err != nil {
			return nil, fmt.Errorf("解析数据文件 %s 失败: %w", s.filePath, err)
		}
		if s.db.Shares == nil {
			s.db.Shares = []Share{}
		}
		if s.db.Audits == nil {
			s.db.Audits = []AuditEvent{}
		}
	}
	return s, nil
}

// DBPath 返回底层 JSON 数据文件路径。
func (s *Store) DBPath() string { return s.filePath }

func (s *Store) persistLocked(data dbData) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化数据失败: %w", err)
	}
	raw = append(raw, '\n')
	if err := s.writeFileAtomic(s.filePath, raw); err != nil {
		return err
	}
	return nil
}

// update 在一个事务中执行变更：先做深拷贝快照，再执行 mutate，
// 最后原子落盘。mutate 返回错误或落盘失败时，内存状态整体恢复为快照，
// 磁盘文件要么是旧版本要么是新版本，不会出现半批撤销。
func (s *Store) update(mutate func(db *dbData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot, err := cloneDB(s.db)
	if err != nil {
		return fmt.Errorf("创建事务快照失败: %w", err)
	}
	if err := mutate(&s.db); err != nil {
		s.db = snapshot
		return err
	}
	if err := s.persistLocked(s.db); err != nil {
		s.db = snapshot
		return fmt.Errorf("提交失败，已整体回滚: %w", err)
	}
	return nil
}

func cloneDB(in dbData) (dbData, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return dbData{}, err
	}
	var out dbData
	if err := json.Unmarshal(raw, &out); err != nil {
		return dbData{}, err
	}
	if out.Shares == nil {
		out.Shares = []Share{}
	}
	if out.Audits == nil {
		out.Audits = []AuditEvent{}
	}
	return out, nil
}

// atomicWriteJSON 在同一目录写临时文件，fsync 后 rename，
// 保证数据文件的原子替换。
func atomicWriteJSON(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".db.json.tmp-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync 临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		cleanup()
		return fmt.Errorf("设置文件权限失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("原子替换数据文件失败: %w", err)
	}
	// fsync 目录，确保 rename 落盘。
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// normalizeDirectory 规范化为斜杠分隔的绝对目录形式。
func normalizeDirectory(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ""
	}
	dir = filepath.ToSlash(dir)
	if !strings.HasPrefix(dir, "/") {
		dir = "/" + dir
	}
	return filepath.Clean(dir)
}

// MatchShare 判断一条分享是否满足筛选条件。
func MatchShare(sh Share, f Filter) bool {
	if owner := strings.TrimSpace(f.Owner); owner != "" {
		if !strings.EqualFold(sh.OwnerName, owner) &&
			!strings.EqualFold(sh.OwnerID, owner) {
			return false
		}
	}
	if dir := normalizeDirectory(f.Directory); dir != "" {
		shareDir := normalizeDirectory(sh.Directory)
		if dir == "/" {
			// 根目录匹配全部。
		} else if f.Recursive {
			if shareDir != dir && !strings.HasPrefix(shareDir, dir+"/") {
				return false
			}
		} else if shareDir != dir {
			return false
		}
	}
	if f.CreatedFrom != nil && sh.CreatedAt.Before(*f.CreatedFrom) {
		return false
	}
	// CreatedTo 为排他上界（日期粒度时由解析层加一天）。
	if f.CreatedTo != nil && !sh.CreatedAt.Before(*f.CreatedTo) {
		return false
	}
	if status := strings.TrimSpace(f.Status); status != "" &&
		!strings.EqualFold(status, "all") &&
		!strings.EqualFold(string(sh.Status), status) {
		return false
	}
	return true
}

// filterShares 返回满足条件的分享（调用方需持有锁或使用只读包装）。
func filterShares(shares []Share, f Filter) []Share {
	out := make([]Share, 0)
	for _, sh := range shares {
		if MatchShare(sh, f) {
			out = append(out, sh)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// Preview 计算筛选结果与受影响文件数，不修改任何数据。
func (s *Store) Preview(f Filter) PreviewInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return buildPreview(s.db.Shares, f)
}

func buildPreview(shares []Share, f Filter) PreviewInfo {
	matched := filterShares(shares, f)
	revocable := make([]Share, 0)
	fileSet := make(map[string]*FileImpact)
	matchedFileSet := make(map[string]struct{})
	for _, sh := range matched {
		matchedFileSet[sh.FileID] = struct{}{}
		if sh.Status != StatusActive {
			continue
		}
		revocable = append(revocable, sh)
		impact, ok := fileSet[sh.FileID]
		if !ok {
			impact = &FileImpact{
				FileID:    sh.FileID,
				FileName:  sh.FileName,
				Directory: sh.Directory,
				OwnerName: sh.OwnerName,
			}
			fileSet[sh.FileID] = impact
		}
		impact.ActiveLinks++
	}
	files := make([]FileImpact, 0, len(fileSet))
	for _, fi := range fileSet {
		files = append(files, *fi)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].FileID < files[j].FileID })

	items := revocable
	if items == nil {
		items = []Share{}
	}
	return PreviewInfo{
		Criteria:       f,
		MatchedLinks:   len(matched),
		MatchedFiles:   len(matchedFileSet),
		RevocableLinks: len(revocable),
		AffectedFiles:  len(files),
		Files:          files,
		Items:          items,
	}
}

// RevokeInput 是执行批量撤销的内部入参。
type RevokeInput struct {
	Filter   Filter
	Reason   string
	Operator string
}

// BatchRevoke 在单个事务内撤销全部匹配的 active 链接并写入审计记录。
// 任意一步失败都会整体回滚，不会留下“撤销了一半”的状态。
func (s *Store) BatchRevoke(in RevokeInput) (*RevokeResult, error) {
	reason := strings.TrimSpace(in.Reason)
	operator := strings.TrimSpace(in.Operator)
	if operator == "" {
		operator = "admin"
	}
	startedAt := s.now()
	batchID := newBatchID(startedAt)

	var result *RevokeResult
	err := s.update(func(db *dbData) error {
		preview := buildPreview(db.Shares, in.Filter)
		if preview.RevocableLinks == 0 {
			return ErrNothingToRevoke
		}

		now := s.now()
		targets := make([]AuditTarget, 0, preview.RevocableLinks)
		shareIDs := make([]string, 0, preview.RevocableLinks)
		fileIDs := make([]string, 0, len(preview.Files))
		for _, fi := range preview.Files {
			fileIDs = append(fileIDs, fi.FileID)
		}

		revoked := 0
		for i := range db.Shares {
			sh := &db.Shares[i]
			if !MatchShare(*sh, in.Filter) || sh.Status != StatusActive {
				continue
			}
			targets = append(targets, AuditTarget{
				ShareID:   sh.ID,
				FileID:    sh.FileID,
				FileName:  sh.FileName,
				Directory: sh.Directory,
				OwnerName: sh.OwnerName,
				LinkToken: sh.LinkToken,
				CreatedAt: sh.CreatedAt,
			})
			shareIDs = append(shareIDs, sh.ID)
			sh.Status = StatusRevoked
			sh.RevokedAt = &now
			sh.RevokeReason = reason
			sh.RevokeBatchID = batchID
			sh.RevokeOperator = operator
			revoked++
		}
		if revoked != preview.RevocableLinks {
			// 理论上不会发生；显式检查以保证“所见即所撤”。
			return fmt.Errorf("撤销数量与预览不一致（%d/%d），事务终止", revoked, preview.RevocableLinks)
		}

		event := AuditEvent{
			BatchID:       batchID,
			Action:        "batch_revoke_shares",
			Operator:      operator,
			Reason:        reason,
			Criteria:      in.Filter,
			MatchedLinks:  preview.MatchedLinks,
			RevokedLinks:  revoked,
			AffectedFiles: preview.AffectedFiles,
			ShareIDs:      shareIDs,
			FileIDs:       fileIDs,
			Targets:       targets,
			StartedAt:     startedAt,
			FinishedAt:    s.now(),
			Outcome:       "committed",
		}
		db.Audits = append(db.Audits, event)

		result = &RevokeResult{
			BatchID:       batchID,
			RevokedLinks:  revoked,
			AffectedFiles: preview.AffectedFiles,
			Reason:        reason,
			Operator:      operator,
			FinishedAt:    event.FinishedAt,
			Audit:         event,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func newBatchID(t time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return "RV-" + t.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// ListShares 返回按创建时间倒序的全量（或筛选后的）分享。
func (s *Store) ListShares(f Filter) []Share {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filterShares(s.db.Shares, f)
}

// ListAudits 返回按完成时间倒序的审计记录。
func (s *Store) ListAudits() []AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditEvent, len(s.db.Audits))
	copy(out, s.db.Audits)
	sort.Slice(out, func(i, j int) bool {
		return out[i].FinishedAt.After(out[j].FinishedAt)
	})
	return out
}

// GetAudit 按批次号取审计记录。
func (s *Store) GetAudit(batchID string) (AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ev := range s.db.Audits {
		if ev.BatchID == batchID {
			return ev, nil
		}
	}
	return AuditEvent{}, ErrNotFound
}

// Meta 给出筛选器可选项：负责人与目录。
type Meta struct {
	Owners      []OwnerOption  `json:"owners"`
	Directories []string       `json:"directories"`
	Statuses    []StatusOption `json:"statuses"`
}

type OwnerOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type StatusOption struct {
	Value ShareStatus `json:"value"`
	Label string      `json:"label"`
}

func (s *Store) GetMeta() Meta {
	s.mu.Lock()
	defer s.mu.Unlock()
	ownerSet := make(map[string]OwnerOption)
	dirSet := make(map[string]struct{})
	for _, sh := range s.db.Shares {
		ownerSet[sh.OwnerID] = OwnerOption{ID: sh.OwnerID, Name: sh.OwnerName}
		dirSet[sh.Directory] = struct{}{}
	}
	owners := make([]OwnerOption, 0, len(ownerSet))
	for _, o := range ownerSet {
		owners = append(owners, o)
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].ID < owners[j].ID })
	dirs := make([]string, 0, len(dirSet))
	for d := range dirSet {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return Meta{
		Owners:      owners,
		Directories: dirs,
		Statuses: []StatusOption{
			{Value: StatusActive, Label: "有效中"},
			{Value: StatusRevoked, Label: "已撤销"},
			{Value: StatusExpired, Label: "已过期"},
		},
	}
}
