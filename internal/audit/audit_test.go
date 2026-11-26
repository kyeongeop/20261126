package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log("tok_1", "publish", "acme/", "billing-api", "1.0.0", Allow, "published")
	l.Log("anonymous", "read", "other/", "x", "1.0.0", Deny, "invalid token")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen: the chain must continue across restarts.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Log("tok_1", "read", "acme/", "billing-api", "1.0.0", Allow, "served")
	l2.Close()
	if err := Verify(path); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log("tok_1", "read", "acme/", "a", "1.0.0", Deny, "scope")
	l.Log("tok_1", "read", "acme/", "a", "1.0.0", Allow, "served")
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a deny into an allow, as an attacker covering tracks would.
	tampered := strings.Replace(string(data), `"deny"`, `"allow"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path); err == nil {
		t.Fatal("tampered log must fail verification")
	}
}
