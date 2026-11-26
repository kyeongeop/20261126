package mfa

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// AccessDecision explains whether an application access attempt is allowed.
type AccessDecision struct {
	Allowed         bool
	Reason          string
	RecoveryWindow  bool
	HighSensitive   bool
	WindowExpiresAt time.Time
}

// CheckAccess enforces the recovery policy:
//
//   - Users with an active MFA registration access every application.
//   - Users inside an approved recovery window may access low-sensitivity
//     applications only; high-sensitivity applications are blocked.
//   - Users whose window has ended (or who never had one) are blocked until
//     they re-register an authenticator.
func (s *Service) CheckAccess(userID, appID string) (AccessDecision, error) {
	user, ok := s.store.GetUser(userID)
	if !ok {
		return AccessDecision{}, ErrNotFound
	}
	app, ok := s.store.GetApp(appID)
	if !ok {
		return AccessDecision{}, ErrNotFound
	}
	now := s.clock()
	s.sweep(now)

	if user.MFAEnrolled {
		return AccessDecision{
			Allowed:       true,
			Reason:        "mfa enrolled",
			HighSensitive: app.HighSensitive,
		}, nil
	}

	req := s.latestRequest(userID)
	if req != nil && req.WindowOpen(now) {
		decision := AccessDecision{
			RecoveryWindow:  true,
			HighSensitive:   app.HighSensitive,
			WindowExpiresAt: req.WindowExpiresAt,
		}
		if app.HighSensitive {
			decision.Reason = "high-sensitivity application blocked during recovery"
			return decision, ErrHighSensitiveBlocked
		}
		decision.Allowed = true
		decision.Reason = "low-sensitivity access allowed during recovery"
		return decision, nil
	}

	return AccessDecision{HighSensitive: app.HighSensitive}, ErrMFARequired
}

// ReEnroll closes the recovery window by registering a new authenticator.
// The caller must present the single-use recovery token delivered out of
// band. Users whose window has expired can re-register without a token at
// the dedicated enrollment step (see EnrollAfterExpiry).
func (s *Service) ReEnroll(actor Actor, requestID, token string) (ResetRequest, error) {
	req, ok := s.store.GetRequest(requestID)
	if !ok {
		return ResetRequest{}, ErrNotFound
	}
	if actor.Role != RoleUser || actor.ID != req.UserID {
		return ResetRequest{}, ErrUnauthorized
	}
	now := s.clock()
	s.sweep(now)
	if req.Status != StatusActive || !req.WindowOpen(now) {
		return ResetRequest{}, ErrWindowExpired
	}
	if strings.TrimSpace(token) == "" ||
		req.RecoveryTokenHash != hashRecoveryToken(strings.TrimSpace(token)) {
		return ResetRequest{}, ErrInvalidRecoveryToken
	}
	return s.completeEnrollment(actor.ID, req, now, "request.reenroll")
}

// EnrollAfterExpiry lets a user whose window has ended register a fresh
// authenticator. This is the mandatory step after expiry, revocation, or
// rejection: normal access stays denied until enrollment succeeds.
func (s *Service) EnrollAfterExpiry(actor Actor, userID, secret string) (User, error) {
	user, ok := s.store.GetUser(userID)
	if !ok {
		return User{}, ErrNotFound
	}
	if actor.Role != RoleUser || actor.ID != user.ID {
		return User{}, ErrUnauthorized
	}
	if strings.TrimSpace(secret) == "" {
		return User{}, joinError(ErrInvalidInput, "authenticator secret is required")
	}
	now := s.clock()
	s.sweep(now)
	if user.MFAEnrolled {
		return User{}, joinError(ErrInvalidTransition, "authenticator already registered")
	}
	user.MFAEnrolled = true
	user.MFASecret = strings.TrimSpace(secret)
	s.store.UpdateUser(user)

	if req := s.latestRequest(userID); req != nil &&
		(req.Status == StatusExpired || req.Status == StatusRevoked) {
		req.Status = StatusReEnrolled
		req.ReEnrolledAt = now
		req.ClosedAt = now
		s.store.UpdateRequest(*req)
		s.store.AppendAudit(AuditEvent{
			Time: now, ActorID: actor.ID, Action: "request.reenroll",
			RequestID: req.ID, Detail: "authenticator registered after window ended",
		})
	} else {
		s.store.AppendAudit(AuditEvent{
			Time: now, ActorID: actor.ID, Action: "user.enroll",
			Detail: "authenticator registered",
		})
	}
	return user, nil
}

// Revoke ends an open recovery window immediately. Only administrators may
// revoke; the user must then re-register an authenticator.
func (s *Service) Revoke(actor Actor, requestID, note string) (ResetRequest, error) {
	req, err := s.requireAdminRequest(actor, requestID)
	if err != nil {
		return ResetRequest{}, err
	}
	now := s.clock()
	s.sweep(now)
	if req.Status != StatusActive {
		return ResetRequest{}, ErrInvalidTransition
	}
	req.Status = StatusRevoked
	req.DecisionNote = strings.TrimSpace(note)
	req.ClosedAt = now
	s.store.UpdateRequest(req)
	s.store.AppendAudit(AuditEvent{
		Time: now, ActorID: actor.ID, Action: "request.revoke",
		RequestID: req.ID, Detail: req.DecisionNote,
	})
	return req, nil
}

// GetRequest returns a request. Users may read their own requests; admins
// may read every request.
func (s *Service) GetRequest(actor Actor, requestID string) (ResetRequest, error) {
	req, ok := s.store.GetRequest(requestID)
	if !ok {
		return ResetRequest{}, ErrNotFound
	}
	if actor.Role != RoleAdmin && actor.ID != req.UserID {
		return ResetRequest{}, ErrUnauthorized
	}
	return req, nil
}

// ListRequests returns requests visible to the actor: an admin sees all, a
// user sees only their own.
func (s *Service) ListRequests(actor Actor) []ResetRequest {
	s.sweep(s.clock())
	if actor.Role == RoleAdmin {
		return s.store.ListRequests()
	}
	return s.store.ListRequestsByUser(actor.ID)
}

func (s *Service) completeEnrollment(actorID string, req ResetRequest, now time.Time, action string) (ResetRequest, error) {
	user, ok := s.store.GetUser(req.UserID)
	if !ok {
		return ResetRequest{}, ErrNotFound
	}
	secret, err := newEnrollmentSecret()
	if err != nil {
		return ResetRequest{}, err
	}
	user.MFAEnrolled = true
	user.MFASecret = secret
	s.store.UpdateUser(user)

	req.Status = StatusReEnrolled
	req.ReEnrolledAt = now
	req.ClosedAt = now
	req.RecoveryTokenHash = ""
	s.store.UpdateRequest(req)
	s.store.AppendAudit(AuditEvent{
		Time: now, ActorID: actorID, Action: action,
		RequestID: req.ID, Detail: "recovery window closed by re-registration",
	})
	return req, nil
}

func (s *Service) latestRequest(userID string) *ResetRequest {
	reqs := s.store.ListRequestsByUser(userID)
	if len(reqs) == 0 {
		return nil
	}
	latest := reqs[len(reqs)-1]
	return &latest
}

// newEnrollmentSecret generates a fresh authenticator secret with
// crypto/rand. The console stores the secret; the user binds it to their
// authenticator app during registration.
func newEnrollmentSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := readRandom(buf); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}
