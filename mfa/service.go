package mfa

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Actor identifies the authenticated console principal performing an action.
type Actor struct {
	ID   string
	Role Role
}

// SubmitInput is the applicant-supplied content of a reset request. All four
// workflow fields are mandatory: loss reason, recovery window, notification
// method, and end condition.
type SubmitInput struct {
	UserID        string
	Reason        string
	WindowMinutes int
	NotifyMethod  NotifyMethod
	EndCondition  EndCondition
}

// Service runs the approval-based MFA reset workflow.
type Service struct {
	store    Store
	notifier Notifier
	clock    Clock
	seq      uint64
}

// NewService wires the workflow to a store, notifier and clock. A nil clock
// defaults to time.Now.
func NewService(store Store, notifier Notifier, clock Clock) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{store: store, notifier: notifier, clock: clock}
}

// SubmitRequest creates a pending reset request. There is deliberately no
// method for an administrator to clear MFA fields directly: access recovery
// always goes through this approval workflow.
func (s *Service) SubmitRequest(actor Actor, in SubmitInput) (ResetRequest, error) {
	user, ok := s.store.GetUser(in.UserID)
	if !ok {
		return ResetRequest{}, ErrNotFound
	}
	if actor.Role != RoleUser || actor.ID != user.ID {
		return ResetRequest{}, ErrUnauthorized
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return ResetRequest{}, joinError(ErrInvalidInput, "lost reason is required")
	}
	if in.WindowMinutes < 1 || in.WindowMinutes > MaxWindowMinutes {
		return ResetRequest{}, joinError(ErrInvalidInput,
			"window minutes must be between 1 and "+strconv.Itoa(MaxWindowMinutes))
	}
	if !in.NotifyMethod.Valid() {
		return ResetRequest{}, joinError(ErrInvalidInput, "unsupported notification method")
	}
	if !in.EndCondition.Valid() {
		return ResetRequest{}, joinError(ErrInvalidInput, "unsupported end condition")
	}
	if in.NotifyMethod == NotifyEmail && strings.TrimSpace(user.Email) == "" {
		return ResetRequest{}, ErrContactMissing
	}
	if in.NotifyMethod == NotifySMS && strings.TrimSpace(user.Phone) == "" {
		return ResetRequest{}, ErrContactMissing
	}

	now := s.clock()
	s.sweep(now)
	for _, existing := range s.store.ListRequestsByUser(user.ID) {
		if existing.Status == StatusPending || existing.WindowOpen(now) {
			return ResetRequest{}, ErrPendingRequest
		}
	}

	req := ResetRequest{
		ID:            s.nextID(),
		UserID:        user.ID,
		Reason:        reason,
		NotifyMethod:  in.NotifyMethod,
		WindowMinutes: in.WindowMinutes,
		EndCondition:  in.EndCondition,
		Status:        StatusPending,
		CreatedAt:     now,
	}
	s.store.CreateRequest(req)
	s.store.AppendAudit(AuditEvent{
		Time: now, ActorID: actor.ID, Action: "request.submit",
		RequestID: req.ID, Detail: reason,
	})
	return req, nil
}

// Approve activates the recovery window and delivers the recovery token
// through the requested channel. Only administrators may approve.
func (s *Service) Approve(actor Actor, requestID, note string) (ResetRequest, error) {
	req, err := s.requireAdminRequest(actor, requestID)
	if err != nil {
		return ResetRequest{}, err
	}
	now := s.clock()
	s.sweep(now)
	if req.Status != StatusPending {
		return ResetRequest{}, ErrInvalidTransition
	}
	user, ok := s.store.GetUser(req.UserID)
	if !ok {
		return ResetRequest{}, ErrNotFound
	}
	// Approving a lost-authenticator claim suspends the old factor for the
	// duration of the workflow. The secret itself is replaced only when the
	// user registers a new authenticator; nothing is cleared silently.
	factorSuspended := user.MFAEnrolled
	user.MFAEnrolled = false
	s.store.UpdateUser(user)
	plaintext, tokenHash, err := newRecoveryToken()
	if err != nil {
		return ResetRequest{}, err
	}
	destination := user.Email
	if req.NotifyMethod == NotifySMS {
		destination = user.Phone
	}

	req.Status = StatusActive
	req.DecidedBy = actor.ID
	req.DecidedAt = now
	req.DecisionNote = strings.TrimSpace(note)
	req.WindowExpiresAt = now.Add(time.Duration(req.WindowMinutes) * time.Minute)
	req.RecoveryTokenHash = tokenHash

	// Deliver before persisting the active state so a notification failure
	// leaves the request pending and the user never locked out silently.
	if err := s.notifier.Send(Notification{
		UserID:      user.ID,
		Method:      req.NotifyMethod,
		Destination: destination,
		RequestID:   req.ID,
		Token:       plaintext,
		ExpiresAt:   req.WindowExpiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		return ResetRequest{}, err
	}
	s.store.UpdateRequest(req)
	s.store.AppendAudit(AuditEvent{
		Time: now, ActorID: actor.ID, Action: "request.approve",
		RequestID: req.ID, Detail: req.DecisionNote,
	})
	if factorSuspended {
		s.store.AppendAudit(AuditEvent{
			Time: now, ActorID: actor.ID, Action: "mfa.suspend",
			RequestID: req.ID,
			Detail:    "previous authenticator suspended pending re-registration",
		})
	}
	return req, nil
}

// Reject closes a pending request without opening any recovery window.
func (s *Service) Reject(actor Actor, requestID, note string) (ResetRequest, error) {
	req, err := s.requireAdminRequest(actor, requestID)
	if err != nil {
		return ResetRequest{}, err
	}
	if strings.TrimSpace(note) == "" {
		return ResetRequest{}, joinError(ErrInvalidInput, "rejection note is required")
	}
	now := s.clock()
	s.sweep(now)
	if req.Status != StatusPending {
		return ResetRequest{}, ErrInvalidTransition
	}
	req.Status = StatusRejected
	req.DecidedBy = actor.ID
	req.DecidedAt = now
	req.DecisionNote = strings.TrimSpace(note)
	req.ClosedAt = now
	s.store.UpdateRequest(req)
	s.store.AppendAudit(AuditEvent{
		Time: now, ActorID: actor.ID, Action: "request.reject",
		RequestID: req.ID, Detail: req.DecisionNote,
	})
	return req, nil
}

func (s *Service) requireAdminRequest(actor Actor, requestID string) (ResetRequest, error) {
	if actor.Role != RoleAdmin {
		return ResetRequest{}, ErrUnauthorized
	}
	req, ok := s.store.GetRequest(requestID)
	if !ok {
		return ResetRequest{}, ErrNotFound
	}
	return req, nil
}

func (s *Service) nextID() string {
	n := atomic.AddUint64(&s.seq, 1)
	return "RR-" + strconv.FormatUint(100000+n, 10)
}

// sweep transitions every active request whose window has elapsed to
// expired. Expired users must re-register an authenticator.
func (s *Service) sweep(now time.Time) {
	for _, req := range s.store.ListRequests() {
		if req.Status == StatusActive && !req.WindowOpen(now) {
			req.Status = StatusExpired
			req.ClosedAt = req.WindowExpiresAt
			s.store.UpdateRequest(req)
			s.store.AppendAudit(AuditEvent{
				Time: now, ActorID: "system", Action: "request.expire",
				RequestID: req.ID,
				Detail:    "recovery window ended; re-registration required",
			})
		}
	}
}
