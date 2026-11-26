package guest_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"guestshare/internal/guest"
)

func TestInvitationLifecycleAndDirectoryMovement(t *testing.T) {
	root := copyFixture(t)
	current := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	service := newService(t, root, func() time.Time { return current })

	created, err := service.CreateInvitation(guest.CreateInvitationParams{
		Inviter:     "team",
		DisplayName: "Lin",
		Directory:   "Design",
		ExpiresAt:   current.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if created.InvitationToken == "" {
		t.Fatal("expected a one-time invitation token")
	}
	if created.Invitation.Directory != "Design" || !created.Invitation.DirectoryAvailable {
		t.Fatalf("unexpected invitation: %+v", created.Invitation)
	}

	joined, err := service.Join(created.InvitationToken, "")
	if err != nil {
		t.Fatalf("join invitation: %v", err)
	}
	session, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatalf("authenticate guest: %v", err)
	}
	entries, err := service.ListDirectory(session, "")
	if err != nil {
		t.Fatalf("list authorized directory: %v", err)
	}
	assertEntryNames(t, entries, "brief.txt", "notes")

	if _, err := service.ListDirectory(session, "../Finance"); !hasCode(err, "path_outside_authorized_directory") {
		t.Fatalf("expected traversal to be blocked, got %v", err)
	}
	file, _, err := service.OpenGuestFile(session, "brief.txt")
	if err != nil {
		t.Fatalf("open authorized file: %v", err)
	}
	contents, err := io.ReadAll(file)
	file.Close()
	if err != nil || len(contents) == 0 {
		t.Fatalf("read authorized file: %v", err)
	}

	movedRoot := filepath.Join(root, "Design 2026")
	if err := os.Rename(filepath.Join(root, "Design"), movedRoot); err != nil {
		t.Fatalf("move authorized directory: %v", err)
	}
	session, err = service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatalf("authenticate after directory move: %v", err)
	}
	if session.Invitation.Directory != "Design 2026" {
		t.Fatalf("directory was not updated after move: %q", session.Invitation.Directory)
	}
	if entries, err = service.ListDirectory(session, ""); err != nil {
		t.Fatalf("list moved directory: %v", err)
	}
	assertEntryNames(t, entries, "brief.txt", "notes")

	invitations := service.ListInvitations("team")
	if len(invitations) != 1 || invitations[0].Directory != "Design 2026" {
		t.Fatalf("admin view did not follow move: %+v", invitations)
	}

	if err := os.RemoveAll(movedRoot); err != nil {
		t.Fatalf("delete authorized directory: %v", err)
	}
	if _, err := service.Authenticate(joined.SessionToken); !hasCode(err, "directory_unavailable") {
		t.Fatalf("expected deleted directory to be unavailable, got %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "Design 2026"), 0o755); err != nil {
		t.Fatalf("recreate old directory path: %v", err)
	}
	if _, err := service.Authenticate(joined.SessionToken); !hasCode(err, "directory_unavailable") {
		t.Fatalf("replacement directory must not inherit access, got %v", err)
	}

	revoked, err := service.RevokeInvitation("team", created.Invitation.ID)
	if err != nil {
		t.Fatalf("revoke invitation: %v", err)
	}
	if revoked.Status != "revoked" {
		t.Fatalf("unexpected revoked status: %s", revoked.Status)
	}
	if _, err := service.Authenticate(joined.SessionToken); !hasCode(err, "invitation_revoked") {
		t.Fatalf("expected revoked invitation, got %v", err)
	}
}

func TestPasscodeAndExpiry(t *testing.T) {
	root := copyFixture(t)
	current := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	service := newService(t, root, func() time.Time { return current })

	created, err := service.CreateInvitation(guest.CreateInvitationParams{
		Inviter:     "team",
		DisplayName: "Visitor",
		Passcode:    "correct horse",
		Directory:   "Public",
		ExpiresAt:   current.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if _, err := service.Join(created.InvitationToken, ""); !hasCode(err, "passcode_required") {
		t.Fatalf("expected passcode requirement, got %v", err)
	}
	if _, err := service.Join(created.InvitationToken, "wrong"); !hasCode(err, "passcode_invalid") {
		t.Fatalf("expected invalid passcode, got %v", err)
	}
	joined, err := service.Join(created.InvitationToken, "correct horse")
	if err != nil {
		t.Fatalf("join with passcode: %v", err)
	}
	current = current.Add(2 * time.Hour)
	if _, err := service.Authenticate(joined.SessionToken); !hasCode(err, "invitation_expired") {
		t.Fatalf("expected expired session, got %v", err)
	}
	if _, err := service.Join(created.InvitationToken, "correct horse"); !hasCode(err, "invitation_expired") {
		t.Fatalf("expected expired join, got %v", err)
	}
}

func TestSessionAndDirectoryStateSurviveRestart(t *testing.T) {
	root := copyFixture(t)
	current := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	dataFile := filepath.Join(t.TempDir(), "state.json")
	service, err := guest.NewService(guest.Config{
		Root: root, DataFile: dataFile, Now: func() time.Time { return current },
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	created, err := service.CreateInvitation(guest.CreateInvitationParams{
		Inviter: "team", DisplayName: "Restart Guest", Directory: "Public",
		ExpiresAt: current.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	joined, err := service.Join(created.InvitationToken, "")
	if err != nil {
		t.Fatalf("join invitation: %v", err)
	}
	if err := os.Rename(filepath.Join(root, "Public"), filepath.Join(root, "Public 2")); err != nil {
		t.Fatalf("move directory: %v", err)
	}

	restarted, err := guest.NewService(guest.Config{
		Root: root, DataFile: dataFile, Now: func() time.Time { return current },
	})
	if err != nil {
		t.Fatalf("restart service: %v", err)
	}
	session, err := restarted.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatalf("authenticate after restart: %v", err)
	}
	if session.Invitation.Directory != "Public 2" {
		t.Fatalf("unexpected directory after restart: %q", session.Invitation.Directory)
	}
}

func TestSymlinkEscapeIsDenied(t *testing.T) {
	root := copyFixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write outside fixture: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "Design", "outside")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	current := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	service := newService(t, root, func() time.Time { return current })
	created, err := service.CreateInvitation(guest.CreateInvitationParams{
		Inviter: "team", DisplayName: "Visitor", Directory: "Design",
		ExpiresAt: current.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	joined, err := service.Join(created.InvitationToken, "")
	if err != nil {
		t.Fatalf("join invitation: %v", err)
	}
	session, err := service.Authenticate(joined.SessionToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if _, err := service.ListDirectory(session, "outside"); !hasCode(err, "path_outside_authorized_directory") {
		t.Fatalf("expected symlink escape to be denied, got %v", err)
	}
}

func TestDirectoryMovedOutsideWithSymlinkIsDenied(t *testing.T) {
	root := copyFixture(t)
	outside := t.TempDir()
	current := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	service := newService(t, root, func() time.Time { return current })
	created, err := service.CreateInvitation(guest.CreateInvitationParams{
		Inviter: "team", DisplayName: "Visitor", Directory: "Design",
		ExpiresAt: current.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	joined, err := service.Join(created.InvitationToken, "")
	if err != nil {
		t.Fatalf("join invitation: %v", err)
	}
	moved := filepath.Join(outside, "Design")
	if err := os.Rename(filepath.Join(root, "Design"), moved); err != nil {
		t.Fatalf("move authorized directory outside root: %v", err)
	}
	if err := os.Symlink(moved, filepath.Join(root, "Design")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := service.Authenticate(joined.SessionToken); !hasCode(err, "directory_unavailable") {
		t.Fatalf("expected outside directory to be denied, got %v", err)
	}
}

func newService(t *testing.T, root string, now func() time.Time) *guest.Service {
	t.Helper()
	service, err := guest.NewService(guest.Config{
		Root:     root,
		DataFile: filepath.Join(t.TempDir(), "state.json"),
		Now:      now,
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	return service
}

func copyFixture(t *testing.T) string {
	t.Helper()
	source := filepath.Join("..", "..", "fixtures", "team")
	destination := t.TempDir()
	if err := copyTree(source, destination); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	return destination
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func assertEntryNames(t *testing.T, entries []guest.EntryView, expected ...string) {
	t.Helper()
	if len(entries) != len(expected) {
		t.Fatalf("got %d entries, want %d: %+v", len(entries), len(expected), entries)
	}
	for i := range expected {
		if entries[i].Name != expected[i] {
			t.Fatalf("entry %d is %q, want %q", i, entries[i].Name, expected[i])
		}
	}
}

func hasCode(err error, code string) bool {
	var appErr *guest.Error
	return errors.As(err, &appErr) && appErr.Code == code
}
