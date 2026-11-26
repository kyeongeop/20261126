package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// CreateDeletionInput 是提交删除申请的输入。
type CreateDeletionInput struct {
	Name            string
	Version         string
	Reason          string
	RequestedBy     string
	RequesterRole   string
	Cooldown        time.Duration
	CooldownSeconds *int64
}

func targetKey(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// CreateDeletion 登记一个待删除申请，包随即进入 pending（冷静期）状态。
func (s *Store) CreateDeletion(in CreateDeletionInput) (*DeletionRequest, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Version = strings.TrimSpace(in.Version)
	if err := validateNameVersion(in.Name, in.Version); err != nil {
		return nil, err
	}
	cooldown := s.cooldown
	if in.CooldownSeconds != nil && *in.CooldownSeconds >= 0 {
		cooldown = time.Duration(*in.CooldownSeconds) * time.Second
	} else if in.Cooldown > 0 {
		cooldown = in.Cooldown
	}

	var view *DeletionRequest
	err := s.save(func() error {
		for _, existing := range s.State.Deletions {
			if existing.PackageName == in.Name && existing.Version == in.Version &&
				(existing.Status == StatusPending || existing.Status == StatusCooldownCompleted) {
				return fmt.Errorf("%w: %s", errAlreadyPending, existing.ID)
			}
		}
		id, number := s.newID("dr", "deletion")
		now := s.now()
		d := &DeletionRequest{
			ID:              id,
			Number:          number,
			PackageName:     in.Name,
			Name:            in.Name,
			Version:         in.Version,
			Target:          targetKey(in.Name, in.Version),
			Reason:          in.Reason,
			Status:          StatusPending,
			RequestedBy:     in.RequestedBy,
			Requester:       in.RequestedBy,
			RequesterRole:   in.RequesterRole,
			CreatedAt:       now,
			CooldownSeconds: int64(cooldown / time.Second),
			ExpiresAt:       now.Add(cooldown),
		}
		s.State.Deletions = append(s.State.Deletions, d)
		view = s.buildViewLocked(d)
		view.Status = StatusPending
		view.State = StatusPending
		view.StoredStatus = StatusPending
		view.StatusLabel = labelFor(StatusPending)
		return nil
	})
	if err != nil {
		if errors.Is(err, errAlreadyPending) {
			if active, getErr := s.ActiveDeletion(in.Name, in.Version); getErr == nil {
				return active, err
			}
		}
		return nil, err
	}
	return view, nil
}

// ActiveDeletion 返回某目标当前未终结的删除申请。
func (s *Store) ActiveDeletion(name, version string) (*DeletionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.State.Deletions) - 1; i >= 0; i-- {
		d := s.State.Deletions[i]
		if d.PackageName == name && d.Version == version &&
			(d.Status == StatusPending || d.Status == StatusCooldownCompleted) {
			return s.buildViewLocked(d), nil
		}
	}
	return nil, errRequestNotFound
}

// GetDeletion 按 ID 返回删除申请视图。
func (s *Store) GetDeletion(id string) (*DeletionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.findDeletionLocked(id)
	if d == nil {
		return nil, errRequestNotFound
	}
	return s.buildViewLocked(d), nil
}

// ListDeletions 返回全部删除申请（新申请在前）。
func (s *Store) ListDeletions() []*DeletionRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*DeletionRequest{}
	for i := len(s.State.Deletions) - 1; i >= 0; i-- {
		out = append(out, s.buildViewLocked(s.State.Deletions[i]))
	}
	return out
}

func (s *Store) findDeletionLocked(id string) *DeletionRequest {
	for _, d := range s.State.Deletions {
		if d.ID == id || fmt.Sprint(d.Number) == id {
			return d
		}
	}
	return nil
}

// WithdrawDeletion 在冷静期（以及届满待确认阶段）撤回申请，包恢复为可用。
func (s *Store) WithdrawDeletion(id, user string) (*DeletionRequest, error) {
	var view *DeletionRequest
	err := s.save(func() error {
		d := s.findDeletionLocked(id)
		if d == nil {
			return errRequestNotFound
		}
		if d.Status != StatusPending && d.Status != StatusCooldownCompleted {
			return fmt.Errorf("%w: request is %s", errInvalidTransition, d.Status)
		}
		now := s.now()
		d.Status = StatusWithdrawn
		d.WithdrawnBy = user
		d.WithdrawnAt = &now
		view = s.buildViewLocked(d)
		return nil
	})
	return view, err
}

// CompleteCooldown 在冷静期届满后做引用检查；被引用的包不能进入 cooldown_completed。
func (s *Store) CompleteCooldown(id string) (*DeletionRequest, error) {
	var view *DeletionRequest
	err := s.save(func() error {
		d := s.findDeletionLocked(id)
		if d == nil {
			return errRequestNotFound
		}
		if d.Status == StatusCooldownCompleted || d.Status == StatusDeleted {
			view = s.buildViewLocked(d)
			return nil
		}
		if d.Status != StatusPending {
			return fmt.Errorf("%w: request is %s", errInvalidTransition, d.Status)
		}
		now := s.now()
		if now.Before(d.ExpiresAt) {
			view = s.buildViewLocked(d)
			return fmt.Errorf("%w: %s remaining", errNotDue, d.ExpiresAt.Sub(now).Truncate(time.Second))
		}
		if refs := s.referrersLocked(d.PackageName); len(refs) > 0 {
			d.Blocked = true
			d.BlockCode = errorCode(errReferenced)
			d.ReferencedBy = refs
			d.BlockReasons = []string{fmt.Sprintf("包 %s 仍被 %d 个活跃包版本引用，不能完成冷静期/删除", d.PackageName, len(refs))}
			view = s.buildViewLocked(d)
			return errReferenced
		}
		d.Blocked = false
		d.BlockCode = ""
		d.BlockReasons = nil
		d.Status = StatusCooldownCompleted
		d.CooldownCompletedAt = &now
		d.ReadyAt = &now
		view = s.buildViewLocked(d)
		return nil
	})
	return view, err
}

// ConfirmDeletion 由“另一个有权限的账号”在届满后确认；通过引用复查后真正删除。
// 调用方负责管理员角色与“确认人 != 申请人”的校验。
func (s *Store) ConfirmDeletion(id, confirmer string) (*DeletionRequest, error) {
	var view *DeletionRequest
	err := s.save(func() error {
		d := s.findDeletionLocked(id)
		if d == nil {
			return errRequestNotFound
		}
		if d.Status == StatusDeleted {
			view = s.buildViewLocked(d)
			return nil
		}
		if d.Status == StatusWithdrawn {
			return fmt.Errorf("%w: request was withdrawn", errInvalidTransition)
		}
		now := s.now()
		if d.Status == StatusPending {
			if now.Before(d.ExpiresAt) {
				view = s.buildViewLocked(d)
				return fmt.Errorf("%w: %s remaining", errNotDue, d.ExpiresAt.Sub(now).Truncate(time.Second))
			}
		}
		if refs := s.referrersLocked(d.PackageName); len(refs) > 0 {
			d.Blocked = true
			d.BlockCode = errorCode(errReferenced)
			d.ReferencedBy = refs
			d.BlockReasons = []string{fmt.Sprintf("包 %s 仍被 %d 个活跃包版本引用，不能完成删除", d.PackageName, len(refs))}
			view = s.buildViewLocked(d)
			return errReferenced
		}
		if d.Status == StatusPending {
			d.CooldownCompletedAt = &now
			d.ReadyAt = &now
		}
		d.Status = StatusDeleted
		d.ConfirmedBy = confirmer
		d.ConfirmedAt = &now
		d.DeletedAt = &now
		s.applyDeletionLocked(d, now)
		view = s.buildViewLocked(d)
		return nil
	})
	return view, err
}

// applyDeletionLocked 把目标版本（或包的全部版本）标记为删除。
func (s *Store) applyDeletionLocked(d *DeletionRequest, now time.Time) {
	pkg, ok := s.State.Packages[d.PackageName]
	if !ok {
		return
	}
	if d.Version != "" {
		if v, exists := pkg.Versions[d.Version]; exists && v != nil {
			v.Deleted = true
			v.DeletedAt = &now
			v.DeletionRequestID = d.ID
		}
		return
	}
	for _, v := range pkg.Versions {
		if v == nil || v.Deleted {
			continue
		}
		v.Deleted = true
		v.DeletedAt = &now
		v.DeletionRequestID = d.ID
	}
}

// buildViewLocked 生成带实时影响分析与状态推导的 DTO。调用方持锁。
func (s *Store) buildViewLocked(d *DeletionRequest) *DeletionRequest {
	v := *d
	v.Name = d.PackageName
	v.Requester = d.RequestedBy
	v.RequestID = d.ID
	v.StoredStatus = d.Status
	v.CreatedBy = d.RequestedBy
	v.DueAt = d.ExpiresAt

	now := s.now()
	if d.Status == StatusPending {
		v.Due = !now.Before(d.ExpiresAt)
		v.Expired = v.Due
		remaining := d.ExpiresAt.Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		v.SecondsRemaining = int64(remaining.Seconds())
		v.ExpiresInSeconds = v.SecondsRemaining
	} else {
		v.Due = d.Status == StatusCooldownCompleted || d.Status == StatusDeleted
		v.Expired = v.Due
		v.SecondsRemaining = 0
		v.ExpiresInSeconds = 0
	}

	impact := s.impactLocked(d.PackageName, d.Version)
	v.Impact = impact
	v.AffectedDownloads = impact.Downloads
	v.AffectedBuilds = impact.Builds
	v.Downloads = impact.Downloads
	v.Builds = impact.Builds
	v.ImpactedDownloads = impact.Downloads
	v.ImpactedBuilds = impact.Builds
	v.ReferencedBy = impact.ReferencedBy
	if len(impact.ReferencedBy) > 0 && d.Status != StatusDeleted && d.Status != StatusWithdrawn {
		v.Blocked = true
		if v.BlockCode == "" {
			v.BlockCode = errorCode(errReferenced)
		}
		if len(v.BlockReasons) == 0 {
			v.BlockReasons = []string{fmt.Sprintf("包 %s 正被 %d 个活跃包版本引用", d.PackageName, impact.ReferrerCount)}
		}
	} else if d.Status == StatusCooldownCompleted || d.Status == StatusDeleted {
		v.Blocked = false
	}

	// 有效状态：冷静期已届满且无引用的 pending 申请，在读取时即呈现为 cooldown_completed；
	// 被引用的申请绝不进入该状态。显式 complete/confirm 会把状态真正落盘。
	effective := d.Status
	if d.Status == StatusPending && v.Due && len(impact.ReferencedBy) == 0 {
		effective = StatusCooldownCompleted
	}
	v.Status = effective
	v.State = effective
	v.StatusLabel = labelFor(effective)

	v.CanWithdraw = d.Status == StatusPending || d.Status == StatusCooldownCompleted
	v.CanComplete = d.Status == StatusPending && v.Due && len(impact.ReferencedBy) == 0
	v.CanConfirm = (effective == StatusCooldownCompleted) && len(impact.ReferencedBy) == 0
	return &v
}
