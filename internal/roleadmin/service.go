package roleadmin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Now   func() time.Time
	NewID func(prefix string) (string, error)
}

type Service struct {
	mu           sync.RWMutex
	roles        map[string]Role
	admins       map[string]Admin
	sensitive    map[string]bool
	requests     map[string]*ChangeRequest
	requestOrder []string
	now          func() time.Time
	newID        func(prefix string) (string, error)
}

func NewService(seed Seed) (*Service, error) {
	return NewServiceWithOptions(seed, Options{})
}

func NewServiceWithOptions(seed Seed, options Options) (*Service, error) {
	service := &Service{
		roles:     make(map[string]Role, len(seed.Roles)),
		admins:    make(map[string]Admin, len(seed.Admins)),
		sensitive: make(map[string]bool, len(seed.SensitiveActions)),
		requests:  make(map[string]*ChangeRequest),
		now:       time.Now,
		newID:     randomID,
	}
	if options.Now != nil {
		service.now = options.Now
	}
	if options.NewID != nil {
		service.newID = options.NewID
	}

	for _, admin := range seed.Admins {
		admin.ID = strings.TrimSpace(admin.ID)
		if admin.ID == "" {
			return nil, fmt.Errorf("seed admin has an empty id")
		}
		if _, exists := service.admins[admin.ID]; exists {
			return nil, fmt.Errorf("duplicate seed admin %q", admin.ID)
		}
		service.admins[admin.ID] = admin
	}
	if len(service.admins) == 0 {
		return nil, fmt.Errorf("seed must contain at least one admin")
	}

	sensitiveActions, err := normalizeActions(seed.SensitiveActions, "sensitive_actions")
	if err != nil {
		return nil, err
	}
	for _, action := range sensitiveActions {
		service.sensitive[action] = true
	}

	for _, rawRole := range seed.Roles {
		role, err := normalizeSeedRole(rawRole)
		if err != nil {
			return nil, err
		}
		if _, exists := service.roles[role.ID]; exists {
			return nil, fmt.Errorf("duplicate seed role %q", role.ID)
		}
		service.roles[role.ID] = role
	}
	for roleID := range service.roles {
		if _, err := effectivePermissions(roleID, service.roles); err != nil {
			return nil, fmt.Errorf("invalid seed role %s: %w", roleID, err)
		}
	}
	return service, nil
}

func (s *Service) ListRoles() []Role {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.roles))
	for id := range s.roles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	roles := make([]Role, 0, len(ids))
	for _, id := range ids {
		roles = append(roles, cloneRole(s.roles[id]))
	}
	return roles
}

func (s *Service) GetRole(roleID string) (Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[roleID]
	if !exists {
		return Role{}, notFound("role %s does not exist", roleID)
	}
	return cloneRole(role), nil
}

func (s *Service) PreviewRoleChange(
	roleID string,
	update RoleUpdate,
	actorID string,
) (PreviewResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireAdmin(actorID); err != nil {
		return PreviewResult{}, err
	}
	result, err := s.previewLocked(roleID, update)
	if err != nil {
		return PreviewResult{}, err
	}
	return result, nil
}

func (s *Service) previewLocked(roleID string, update RoleUpdate) (PreviewResult, error) {
	base, exists := s.roles[roleID]
	if !exists {
		return PreviewResult{}, notFound("role %s does not exist", roleID)
	}
	target, err := normalizeRoleUpdate(base, update)
	if err != nil {
		return PreviewResult{}, err
	}
	diff, err := buildRoleDiff(cloneRole(base), target, s.roles, s.sensitive)
	if err != nil {
		return PreviewResult{}, err
	}
	return PreviewResult{
		RoleID:       roleID,
		Diff:         diff,
		ProposedRole: cloneRole(target),
	}, nil
}

func (s *Service) SubmitRoleChange(
	roleID string,
	update RoleUpdate,
	actorID string,
) (ChangeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireAdmin(actorID); err != nil {
		return ChangeRequest{}, err
	}
	preview, err := s.previewLocked(roleID, update)
	if err != nil {
		return ChangeRequest{}, err
	}
	requestID, err := s.nextRequestID()
	if err != nil {
		return ChangeRequest{}, err
	}

	now := s.now().UTC()
	request := ChangeRequest{
		ID:           requestID,
		RoleID:       roleID,
		BaseVersion:  preview.Diff.BaseVersion,
		Status:       ChangePending,
		RequestedBy:  actorID,
		RequestedAt:  now,
		Diff:         preview.Diff,
		ProposedRole: preview.ProposedRole,
		Approval: ApprovalState{
			Required: preview.Diff.RequiresApproval,
			Items:    preview.Diff.ApprovalItems,
		},
	}
	if !preview.Diff.RequiresApproval {
		applied := cloneRole(preview.ProposedRole)
		s.roles[roleID] = applied
		request.Status = ChangeApplied
		request.AppliedRole = &applied
	}
	s.requests[request.ID] = &request
	s.requestOrder = append(s.requestOrder, request.ID)
	return cloneChangeRequest(request), nil
}

func (s *Service) ListChangeRequests() []ChangeRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	requests := make([]ChangeRequest, 0, len(s.requestOrder))
	for i := len(s.requestOrder) - 1; i >= 0; i-- {
		requests = append(requests, cloneChangeRequest(*s.requests[s.requestOrder[i]]))
	}
	return requests
}

func (s *Service) GetChangeRequest(requestID string) (ChangeRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	request, exists := s.requests[requestID]
	if !exists {
		return ChangeRequest{}, notFound("change request %s does not exist", requestID)
	}
	return cloneChangeRequest(*request), nil
}

func (s *Service) DecideChangeRequest(
	requestID string,
	actorID string,
	input DecisionInput,
) (ChangeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireAdmin(actorID); err != nil {
		return ChangeRequest{}, err
	}
	request, exists := s.requests[requestID]
	if !exists {
		return ChangeRequest{}, notFound("change request %s does not exist", requestID)
	}
	if request.Status != ChangePending {
		return ChangeRequest{}, conflict(
			"request_already_decided",
			"change request %s is already %s",
			request.ID,
			request.Status,
		)
	}
	if request.RequestedBy == actorID {
		return ChangeRequest{}, forbidden(
			"second_admin_required",
			"the requesting administrator cannot approve their own change",
		)
	}
	current, exists := s.roles[request.RoleID]
	if !exists {
		return ChangeRequest{}, notFound("role %s does not exist", request.RoleID)
	}
	if current.Version != request.BaseVersion {
		return ChangeRequest{}, conflict(
			"role_version_changed",
			"role %s changed from version %d to %d after this request was created",
			request.RoleID,
			request.BaseVersion,
			current.Version,
		)
	}

	decision := strings.ToLower(strings.TrimSpace(input.Decision))
	now := s.now().UTC()
	switch decision {
	case "reject", "rejected", "deny":
		if input.ApproveAll || len(input.ApprovedActions) > 0 || len(input.ApprovedItemIDs) > 0 {
			return ChangeRequest{}, badRequest(
				"invalid_decision",
				"a rejection cannot include approved actions",
			)
		}
		request.Status = ChangeRejected
		request.Approval.RejectedActions = allApprovalActions(request.Approval.Items)
		request.Approval.DecidedBy = actorID
		request.Approval.DecidedAt = &now
		request.Approval.Comment = input.Comment
	case "approve", "approved", "approve_selected":
		selected, err := selectApprovalItems(request.Approval.Items, input)
		if err != nil {
			return ChangeRequest{}, err
		}
		finalRole := applyApprovedSelection(request.ProposedRole, request.Approval.Items, selected)
		finalRole.Version = request.BaseVersion + 1
		s.roles[request.RoleID] = cloneRole(finalRole)

		approvedIDs := make([]string, 0, len(selected))
		for itemID := range selected {
			approvedIDs = append(approvedIDs, itemID)
		}
		sort.Strings(approvedIDs)
		request.Status = ChangeApplied
		request.AppliedRole = &finalRole
		request.Approval.ApprovedItemIDs = approvedIDs
		request.Approval.ApprovedActions = selectedActions(request.Approval.Items, selected, true)
		request.Approval.RejectedActions = selectedActions(request.Approval.Items, selected, false)
		request.Approval.DecidedBy = actorID
		request.Approval.DecidedAt = &now
		request.Approval.Comment = input.Comment
		request.Approval.Partial = len(selected) < len(request.Approval.Items)
	default:
		return ChangeRequest{}, badRequest(
			"invalid_decision",
			"decision must be approve or reject",
		)
	}
	return cloneChangeRequest(*request), nil
}

func (s *Service) requireAdmin(adminID string) error {
	adminID = strings.TrimSpace(adminID)
	if adminID == "" {
		return unauthorized("admin_required", "X-Admin-ID is required")
	}
	if _, exists := s.admins[adminID]; !exists {
		return forbidden("admin_required", "%s is not an administrator", adminID)
	}
	return nil
}

func (s *Service) nextRequestID() (string, error) {
	for range 5 {
		requestID, err := s.newID("cr")
		if err != nil {
			return "", err
		}
		if _, exists := s.requests[requestID]; !exists {
			return requestID, nil
		}
	}
	return "", fmt.Errorf("could not allocate a unique change request id")
}

func randomID(prefix string) (string, error) {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}

func normalizeSeedRole(role Role) (Role, error) {
	role.ID = strings.TrimSpace(role.ID)
	role.Name = strings.TrimSpace(role.Name)
	if role.ID == "" {
		return Role{}, fmt.Errorf("seed role has an empty id")
	}
	if role.Name == "" {
		return Role{}, fmt.Errorf("seed role %s has an empty name", role.ID)
	}
	if role.Version <= 0 {
		role.Version = 1
	}
	direct, err := normalizeActions(role.DirectPermissions, "direct_permissions")
	if err != nil {
		return Role{}, err
	}
	parents, err := normalizeIdentifiers(role.ParentRoleIDs, "parent_role_ids")
	if err != nil {
		return Role{}, err
	}
	excluded, err := normalizeActions(role.ExcludedPermissions, "excluded_permissions")
	if err != nil {
		return Role{}, err
	}
	role.DirectPermissions = direct
	role.ParentRoleIDs = parents
	role.ExcludedPermissions = excluded
	return role, nil
}
