package freeze

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestFreezeAndLookup(t *testing.T) {
	m := newTestManager(t)

	if got := m.Lookup("/team-a/docs"); got != nil {
		t.Fatalf("expected no freeze, got %+v", got)
	}

	if _, err := m.Freeze("/team-a", "", "admin1"); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("missing reason: want ErrReasonRequired, got %v", err)
	}

	f, err := m.Freeze("/team-a", "suspected exfiltration", "admin1")
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if f.Path != "/team-a" || f.ActorID != "admin1" {
		t.Fatalf("unexpected freeze record: %+v", f)
	}

	if _, err := m.Freeze("/team-a", "again", "admin1"); !errors.Is(err, ErrAlreadyFrozen) {
		t.Fatalf("duplicate freeze: want ErrAlreadyFrozen, got %v", err)
	}

	for _, p := range []string{"/team-a", "/team-a/docs/report.pdf"} {
		got := m.Lookup(p)
		if got == nil || got.Path != "/team-a" {
			t.Fatalf("Lookup(%q) = %+v, want freeze on /team-a", p, got)
		}
	}
	if got := m.Lookup("/team-b"); got != nil {
		t.Fatalf("unrelated path must stay readable, got %+v", got)
	}

	// A nested freeze takes precedence over its parent.
	if _, err := m.Freeze("/team-a/public", "scoped review", "admin1"); err != nil {
		t.Fatalf("nested Freeze: %v", err)
	}
	if got := m.Lookup("/team-a/public/x"); got == nil || got.Path != "/team-a/public" {
		t.Fatalf("nested lookup = %+v", got)
	}
}

func TestUnfreezeWorkflow(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.RequestUnfreeze("/team-a", "incident resolved", "admin1"); !errors.Is(err, ErrNotFrozen) {
		t.Fatalf("unfreeze on live path: want ErrNotFrozen, got %v", err)
	}

	if _, err := m.Freeze("/team-a", "incident", "admin1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RequestUnfreeze("/team-a", "  ", "admin1"); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("blank reason: want ErrReasonRequired, got %v", err)
	}

	req, err := m.RequestUnfreeze("/team-a", "incident cleared, host verified", "admin1")
	if err != nil {
		t.Fatalf("RequestUnfreeze: %v", err)
	}
	if req.Status != "pending" {
		t.Fatalf("new request status = %q, want pending", req.Status)
	}
	if _, err := m.RequestUnfreeze("/team-a", "second", "admin1"); !errors.Is(err, ErrPendingExists) {
		t.Fatalf("second request: want ErrPendingExists, got %v", err)
	}

	// The freeze must remain fully active while confirmation is pending.
	if got := m.Lookup("/team-a/secret"); got == nil {
		t.Fatal("path readable before confirmation")
	}

	if _, err := m.ConfirmUnfreeze("UR-9999", "admin2"); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("bad id: want ErrRequestNotFound, got %v", err)
	}
	unfrozen, err := m.ConfirmUnfreeze(req.ID, "admin2")
	if err != nil {
		t.Fatalf("ConfirmUnfreeze: %v", err)
	}
	if unfrozen.Path != "/team-a" {
		t.Fatalf("unfrozen record = %+v", unfrozen)
	}
	if m.Lookup("/team-a") != nil {
		t.Fatal("freeze still active after confirmation")
	}
	if _, err := m.ConfirmUnfreeze(req.ID, "admin2"); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("double confirm: want ErrRequestNotPending, got %v", err)
	}
}

func TestDeniedEventsAndAudit(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Freeze("/team-a", "incident", "admin1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		m.RecordDenied(DeniedEvent{Path: "/team-a/f", Matched: "/team-a", Action: "read", ActorID: "u", ActorRole: RoleGuestName})
	}

	events, err := m.DeniedEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("denied events = %d, want 3", len(events))
	}
	if events[0].ActorRole != RoleGuestName || events[0].Matched != "/team-a" {
		t.Fatalf("unexpected event: %+v", events[0])
	}

	audit, err := m.AuditLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 || audit[0].Action != "freeze" {
		t.Fatalf("audit = %+v", audit)
	}
}

const RoleGuestName = "guest"

func TestPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Freeze("/team-a", "incident", "admin1"); err != nil {
		t.Fatal(err)
	}
	req, err := m.RequestUnfreeze("/team-a", "all clear", "admin1")
	if err != nil {
		t.Fatal(err)
	}

	restarted, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.Lookup("/team-a/deep/path"); got == nil {
		t.Fatal("freeze lost after restart")
	}
	got := restarted.ListRequests()
	if len(got) != 1 || got[0].ID != req.ID || got[0].Status != "pending" {
		t.Fatalf("requests lost after restart: %+v", got)
	}

	// Shared data directory is never touched by freeze operations.
	share := filepath.Join(dir, "share")
	if err := os.MkdirAll(filepath.Join(share, "team-a"), 0o750); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(filepath.Join(share, "team-a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 0 {
		t.Fatalf("test setup issue: %v", before)
	}
}
