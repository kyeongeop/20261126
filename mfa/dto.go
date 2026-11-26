package mfa

import "time"

// requestResponse is the client-safe representation of a ResetRequest.
// Recovery token hashes never leave the service.
type requestResponse struct {
	ID              string        `json:"id"`
	UserID          string        `json:"user_id"`
	Reason          string        `json:"reason"`
	NotifyMethod    NotifyMethod  `json:"notify_method"`
	WindowMinutes   int           `json:"window_minutes"`
	EndCondition    EndCondition  `json:"end_condition"`
	Status          RequestStatus `json:"status"`
	CreatedAt       time.Time     `json:"created_at"`
	DecidedBy       string        `json:"decided_by,omitempty"`
	DecidedAt       *time.Time    `json:"decided_at,omitempty"`
	DecisionNote    string        `json:"decision_note,omitempty"`
	WindowExpiresAt *time.Time    `json:"window_expires_at,omitempty"`
	ReEnrolledAt    *time.Time    `json:"re_enrolled_at,omitempty"`
	ClosedAt        *time.Time    `json:"closed_at,omitempty"`
}

type userResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Role        Role   `json:"role"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	MFAEnrolled bool   `json:"mfa_enrolled"`
}

type accessResponse struct {
	Allowed         bool      `json:"allowed"`
	Reason          string    `json:"reason"`
	RecoveryWindow  bool      `json:"recovery_window"`
	HighSensitive   bool      `json:"high_sensitive"`
	WindowExpiresAt time.Time `json:"window_expires_at,omitempty"`
}

func toRequestResponse(req ResetRequest) requestResponse {
	out := requestResponse{
		ID:            req.ID,
		UserID:        req.UserID,
		Reason:        req.Reason,
		NotifyMethod:  req.NotifyMethod,
		WindowMinutes: req.WindowMinutes,
		EndCondition:  req.EndCondition,
		Status:        req.Status,
		CreatedAt:     req.CreatedAt,
		DecidedBy:     req.DecidedBy,
		DecisionNote:  req.DecisionNote,
	}
	if !req.DecidedAt.IsZero() {
		t := req.DecidedAt
		out.DecidedAt = &t
	}
	if !req.WindowExpiresAt.IsZero() {
		t := req.WindowExpiresAt
		out.WindowExpiresAt = &t
	}
	if !req.ReEnrolledAt.IsZero() {
		t := req.ReEnrolledAt
		out.ReEnrolledAt = &t
	}
	if !req.ClosedAt.IsZero() {
		t := req.ClosedAt
		out.ClosedAt = &t
	}
	return out
}

func toUserResponse(user User) userResponse {
	return userResponse{
		ID:          user.ID,
		Name:        user.Name,
		Role:        user.Role,
		Email:       user.Email,
		Phone:       user.Phone,
		MFAEnrolled: user.MFAEnrolled,
	}
}

func toAccessResponse(d AccessDecision) accessResponse {
	return accessResponse{
		Allowed:         d.Allowed,
		Reason:          d.Reason,
		RecoveryWindow:  d.RecoveryWindow,
		HighSensitive:   d.HighSensitive,
		WindowExpiresAt: d.WindowExpiresAt,
	}
}
