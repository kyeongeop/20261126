package mfa

import (
	"errors"
	"testing"
	"time"
)

func TestApprovalSuspendsPreviousFactor(t *testing.T) {
	env := newTestEnv()
	env.openRequest(30)

	user, _ := env.store.GetUser("u-alice")
	if user.MFAEnrolled {
		t.Fatal("old MFA factor must be suspended while the recovery window is open")
	}
	if user.MFASecret != "original-secret" {
		t.Fatal("stored secret should remain until re-registration replaces it")
	}
}

func TestRecoveryWindowBlocksHighSensitiveApp(t *testing.T) {
	env := newTestEnv()
	env.openRequest(60)

	low, err := env.service.CheckAccess("u-alice", "app-low")
	if err != nil {
		t.Fatalf("low-sensitivity access: %v", err)
	}
	if !low.Allowed || !low.RecoveryWindow {
		t.Fatalf("low-sensitivity decision = %+v", low)
	}

	high, err := env.service.CheckAccess("u-alice", "app-high")
	if !errors.Is(err, ErrHighSensitiveBlocked) {
		t.Fatalf("high-sensitivity access: got %v, want ErrHighSensitiveBlocked", err)
	}
	if high.Allowed || !high.HighSensitive {
		t.Fatalf("high-sensitivity decision = %+v", high)
	}
}

func TestWindowExpiryForcesReRegistration(t *testing.T) {
	env := newTestEnv()
	req, token := env.openRequest(30)

	env.clock.advance(31 * time.Minute)

	if _, err := env.service.CheckAccess("u-alice", "app-low"); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("access after expiry: got %v, want ErrMFARequired", err)
	}
	if _, err := env.service.ReEnroll(env.alice(), req.ID, token); !errors.Is(err, ErrWindowExpired) {
		t.Fatalf("token use after expiry: got %v, want ErrWindowExpired", err)
	}

	expired, err := env.service.GetRequest(env.alice(), req.ID)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if expired.Status != StatusExpired {
		t.Fatalf("status = %q, want expired", expired.Status)
	}

	user, err := env.service.EnrollAfterExpiry(env.alice(), "u-alice", "new-secret")
	if err != nil {
		t.Fatalf("enroll after expiry: %v", err)
	}
	if !user.MFAEnrolled || user.MFASecret != "new-secret" {
		t.Fatalf("user after enrollment = %+v", user)
	}

	closed, _ := env.store.GetRequest(req.ID)
	if closed.Status != StatusReEnrolled {
		t.Fatalf("request status after enrollment = %q, want reenrolled", closed.Status)
	}
	decision, err := env.service.CheckAccess("u-alice", "app-high")
	if err != nil || !decision.Allowed {
		t.Fatalf("high-sensitivity access after re-registration: %+v err=%v", decision, err)
	}
}

func TestReEnrollWithRecoveryTokenClosesWindow(t *testing.T) {
	env := newTestEnv()
	req, token := env.openRequest(60)

	if _, err := env.service.ReEnroll(env.alice(), req.ID, "wrong-token"); !errors.Is(err, ErrInvalidRecoveryToken) {
		t.Fatalf("wrong token: got %v, want ErrInvalidRecoveryToken", err)
	}

	closed, err := env.service.ReEnroll(env.alice(), req.ID, token)
	if err != nil {
		t.Fatalf("reenroll: %v", err)
	}
	if closed.Status != StatusReEnrolled || closed.RecoveryTokenHash != "" {
		t.Fatalf("request after reenroll = %+v", closed)
	}
	if closed.ReEnrolledAt.IsZero() {
		t.Fatal("re-enrollment timestamp not recorded")
	}

	user, _ := env.store.GetUser("u-alice")
	if !user.MFAEnrolled || user.MFASecret == "original-secret" {
		t.Fatalf("authenticator not replaced: %+v", user)
	}
	if _, err := env.service.ReEnroll(env.alice(), req.ID, token); !errors.Is(err, ErrWindowExpired) {
		t.Fatalf("token reuse: got %v, want ErrWindowExpired", err)
	}
}

func TestRevokeEndsWindowAndRequiresReRegistration(t *testing.T) {
	env := newTestEnv()
	req, _ := env.openRequest(30)

	if _, err := env.service.Revoke(env.alice(), req.ID, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("user revoke: got %v, want ErrUnauthorized", err)
	}
	revoked, err := env.service.Revoke(env.admin(), req.ID, "fraud signal received")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != StatusRevoked {
		t.Fatalf("status = %q, want revoked", revoked.Status)
	}
	if _, err := env.service.CheckAccess("u-alice", "app-low"); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("access after revoke: got %v, want ErrMFARequired", err)
	}

	user, err := env.service.EnrollAfterExpiry(env.alice(), "u-alice", "replacement-secret")
	if err != nil {
		t.Fatalf("enroll after revoke: %v", err)
	}
	if !user.MFAEnrolled {
		t.Fatal("re-registration must restore access")
	}
}

func TestNewRequestAllowedAfterWindowClosed(t *testing.T) {
	env := newTestEnv()
	req, _ := env.openRequest(15)
	env.clock.advance(16 * time.Minute)

	if got := env.service.ListRequests(env.alice()); got[0].Status != StatusExpired {
		t.Fatalf("old request status = %q, want expired", got[0].Status)
	}
	next, err := env.service.SubmitRequest(env.alice(), SubmitInput{
		UserID: "u-alice", Reason: "replacement phone also lost", WindowMinutes: 20,
		NotifyMethod: NotifyEmail, EndCondition: EndConditionReEnrollment,
	})
	if err != nil {
		t.Fatalf("new request after expiry: %v", err)
	}
	if next.ID == req.ID {
		t.Fatal("expected a new request id")
	}
}

func TestAccessCheckUnknownResources(t *testing.T) {
	env := newTestEnv()
	if _, err := env.service.CheckAccess("u-nobody", "app-low"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: got %v, want ErrNotFound", err)
	}
	if _, err := env.service.CheckAccess("u-alice", "app-nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown app: got %v, want ErrNotFound", err)
	}
}

func TestEnrolledUserAccessMarksAppSensitivity(t *testing.T) {
	env := newTestEnv()

	decision, err := env.service.CheckAccess("u-alice", "app-high")
	if err != nil {
		t.Fatalf("enrolled high-sensitivity access: %v", err)
	}
	if !decision.Allowed || !decision.HighSensitive {
		t.Fatalf("decision = %+v, want allowed high-sensitive access", decision)
	}
}

func TestListRequestsIsScopedByRole(t *testing.T) {
	env := newTestEnv()
	env.openRequest(30)

	adminReqs := env.service.ListRequests(env.admin())
	if len(adminReqs) != 1 {
		t.Fatalf("admin sees %d requests, want 1", len(adminReqs))
	}
	other := env.service.ListRequests(Actor{ID: "u-bob", Role: RoleUser})
	if len(other) != 0 {
		t.Fatalf("bob must not see alice's requests, got %d", len(other))
	}
}
