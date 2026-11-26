package mfa

import (
	"errors"
	"testing"
	"time"
)

func TestSubmitRequestRequiresAllWorkflowFields(t *testing.T) {
	env := newTestEnv()

	cases := []struct {
		name string
		in   SubmitInput
		want error
	}{
		{"missing reason", SubmitInput{UserID: "u-alice", WindowMinutes: 30, NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry}, ErrInvalidInput},
		{"zero window", SubmitInput{UserID: "u-alice", Reason: "lost", WindowMinutes: 0, NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry}, ErrInvalidInput},
		{"window too long", SubmitInput{UserID: "u-alice", Reason: "lost", WindowMinutes: MaxWindowMinutes + 1, NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry}, ErrInvalidInput},
		{"bad notify method", SubmitInput{UserID: "u-alice", Reason: "lost", WindowMinutes: 30, NotifyMethod: "pager", EndCondition: EndConditionWindowExpiry}, ErrInvalidInput},
		{"bad end condition", SubmitInput{UserID: "u-alice", Reason: "lost", WindowMinutes: 30, NotifyMethod: NotifyEmail, EndCondition: "never"}, ErrInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := env.service.SubmitRequest(env.alice(), tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSubmitRequestChecksNotificationContact(t *testing.T) {
	env := newTestEnv()
	bob := Actor{ID: "u-bob", Role: RoleUser}

	_, err := env.service.SubmitRequest(bob, SubmitInput{
		UserID: "u-bob", Reason: "device wiped", WindowMinutes: 30,
		NotifyMethod: NotifySMS, EndCondition: EndConditionReEnrollment,
	})
	if !errors.Is(err, ErrContactMissing) {
		t.Fatalf("got %v, want ErrContactMissing", err)
	}
}

func TestSubmitRequestOnlyByOwner(t *testing.T) {
	env := newTestEnv()

	_, err := env.service.SubmitRequest(Actor{ID: "u-bob", Role: RoleUser}, SubmitInput{
		UserID: "u-alice", Reason: "lost", WindowMinutes: 30,
		NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry,
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("user filing for another user: got %v, want ErrUnauthorized", err)
	}

	_, err = env.service.SubmitRequest(env.admin(), SubmitInput{
		UserID: "u-alice", Reason: "lost", WindowMinutes: 30,
		NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry,
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("admin filing on behalf of user: got %v, want ErrUnauthorized", err)
	}
}

func TestSubmitRequestBlocksDuplicateWhileOpen(t *testing.T) {
	env := newTestEnv()
	if _, err := env.service.SubmitRequest(env.alice(), SubmitInput{
		UserID: "u-alice", Reason: "first loss", WindowMinutes: 30,
		NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry,
	}); err != nil {
		t.Fatalf("first request: %v", err)
	}

	_, err := env.service.SubmitRequest(env.alice(), SubmitInput{
		UserID: "u-alice", Reason: "second loss", WindowMinutes: 30,
		NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry,
	})
	if !errors.Is(err, ErrPendingRequest) {
		t.Fatalf("got %v, want ErrPendingRequest", err)
	}
}

func TestApproveOpensWindowAndDeliversToken(t *testing.T) {
	env := newTestEnv()
	req, err := env.service.SubmitRequest(env.alice(), SubmitInput{
		UserID: "u-alice", Reason: "phone stolen", WindowMinutes: 45,
		NotifyMethod: NotifySMS, EndCondition: EndConditionReEnrollment,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	active, err := env.service.Approve(env.admin(), req.ID, "video verified")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if active.Status != StatusActive {
		t.Fatalf("status = %q, want active", active.Status)
	}
	wantExpiry := env.clock.get().Add(45 * time.Minute)
	if !active.WindowExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expiry = %v, want %v", active.WindowExpiresAt, wantExpiry)
	}
	if active.RecoveryTokenHash == "" {
		t.Fatal("recovery token hash not stored")
	}

	notes := env.notifier.All()
	if len(notes) != 1 {
		t.Fatalf("notifications = %d, want 1", len(notes))
	}
	note := notes[0]
	if note.Method != NotifySMS || note.Destination != "+10000000001" {
		t.Fatalf("delivery = %+v, want SMS to alice's phone", note)
	}
	if note.Token == "" || hashRecoveryToken(note.Token) != active.RecoveryTokenHash {
		t.Fatal("delivered token does not match stored hash")
	}

	trail := env.store.AuditTrail()
	if trail[0].Action != "request.submit" || trail[1].Action != "request.approve" {
		t.Fatalf("audit actions = %v", []string{trail[0].Action, trail[1].Action})
	}
}

func TestApproveRequiresAdminAndPendingState(t *testing.T) {
	env := newTestEnv()
	req, err := env.service.SubmitRequest(env.alice(), SubmitInput{
		UserID: "u-alice", Reason: "lost", WindowMinutes: 30,
		NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if _, err := env.service.Approve(env.alice(), req.ID, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-admin approve: got %v, want ErrUnauthorized", err)
	}
	if _, err := env.service.Approve(env.admin(), "RR-999999", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing request: got %v, want ErrNotFound", err)
	}

	if _, err := env.service.Reject(env.admin(), req.ID, "could not verify identity"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if _, err := env.service.Approve(env.admin(), req.ID, "late"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("approve after reject: got %v, want ErrInvalidTransition", err)
	}
}

func TestRejectRequiresNoteAndClosesRequest(t *testing.T) {
	env := newTestEnv()
	req, err := env.service.SubmitRequest(env.alice(), SubmitInput{
		UserID: "u-alice", Reason: "lost", WindowMinutes: 30,
		NotifyMethod: NotifyEmail, EndCondition: EndConditionWindowExpiry,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if _, err := env.service.Reject(env.admin(), req.ID, "  "); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("blank note: got %v, want ErrInvalidInput", err)
	}
	rejected, err := env.service.Reject(env.admin(), req.ID, "impersonation suspected")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.Status != StatusRejected || rejected.ClosedAt.IsZero() {
		t.Fatalf("rejected request not closed: %+v", rejected)
	}
	if len(env.notifier.All()) != 0 {
		t.Fatal("rejection must not deliver a recovery token")
	}
	if user, _ := env.store.GetUser("u-alice"); !user.MFAEnrolled {
		t.Fatal("rejection must not touch the user's existing MFA registration")
	}
}
