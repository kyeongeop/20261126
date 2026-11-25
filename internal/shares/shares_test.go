package shares

import (
	"path/filepath"
	"testing"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shares.json")
	mgr, err := NewManager(path, 1000)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func TestCreateAndVerify(t *testing.T) {
	mgr := newTestManager(t)

	record, err := mgr.Create("report.pdf", "correct horse", []byte("secret bytes"), "2026-11-26T10:00:00Z")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if record.ID == "" || len(record.PasswordHash) == 0 {
		t.Fatalf("record missing ID/hash: %+v", record)
	}

	exists, ok, err := mgr.Verify(record.ID, "correct horse")
	if err != nil || !exists || !ok {
		t.Fatalf("expected successful verify, got exists=%v ok=%v err=%v", exists, ok, err)
	}

	_, wrong, err := mgr.Verify(record.ID, "wrong horse")
	if err != nil || wrong {
		t.Fatalf("expected failed verify, got ok=%v err=%v", wrong, err)
	}
}

func TestVerifyUnknownIDRunsDummyPath(t *testing.T) {
	mgr := newTestManager(t)

	// Must return the same boolean shape as a wrong password and must
	// not error: the dummy derivation and comparison run internally.
	exists, ok, err := mgr.Verify("does-not-exist", "anything")
	if err != nil {
		t.Fatalf("dummy verify errored: %v", err)
	}
	if exists || ok {
		t.Fatalf("unknown share must verify false, got exists=%v ok=%v", exists, ok)
	}
}

func TestPasswordIsNotStoredInPlaintext(t *testing.T) {
	mgr := newTestManager(t)
	password := "plaintext-must-not-appear"

	record, err := mgr.Create("notes.txt", password, nil, "2026-11-26T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{record.PasswordHash, record.Salt} {
		if string(field) == password {
			t.Fatal("password material leaked into stored fields")
		}
	}
}

func TestPersistedSharesSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shares.json")
	mgr, err := NewManager(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	record, err := mgr.Create("a.bin", "pw", []byte("data"), "2026-11-26T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := NewManager(path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	exists, ok, err := reopened.Verify(record.ID, "pw")
	if err != nil || !exists || !ok {
		t.Fatalf("reopened store verify failed: exists=%v ok=%v err=%v", exists, ok, err)
	}
}
