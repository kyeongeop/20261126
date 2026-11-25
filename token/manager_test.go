package token_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"previewtoken/token"
)

func newTestManager(t *testing.T, now *time.Time) *token.Manager {
	t.Helper()
	secret := []byte("unit-test-secret-0123456789abcdef")
	store := token.NewJSONStore(filepath.Join(t.TempDir(), "tokens.json"))
	opts := []token.Option{token.WithDefaultTTL(time.Minute)}
	if now != nil {
		opts = append(opts, token.WithClock(func() time.Time { return *now }))
	}
	mgr, err := token.NewManager(secret, store, opts...)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func sampleIssue(overrides ...func(*token.IssueRequest)) token.IssueRequest {
	req := token.IssueRequest{
		File:    "design/homepage-v3.fig",
		Version: "v3",
		User:    "alice@example.com",
		Purpose: token.PurposePreview,
		TTL:     10 * time.Minute,
	}
	for _, fn := range overrides {
		fn(&req)
	}
	return req
}

func TestIssueAndConsumeRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	mgr := newTestManager(t, &now)

	raw, claims, err := mgr.Issue(sampleIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if raw == "" || claims.JTI == "" {
		t.Fatal("expected non-empty token and jti")
	}

	got, err := mgr.Consume(raw, token.Binding{
		File:    "design/homepage-v3.fig",
		Version: "v3",
		User:    "alice@example.com",
		Purpose: token.PurposePreview,
	})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.File != claims.File || got.Version != claims.Version ||
		got.User != claims.User || got.Purpose != claims.Purpose {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if !got.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("unexpected expiry: %v", got.ExpiresAt)
	}
}

func TestReplayIsRejected(t *testing.T) {
	mgr := newTestManager(t, nil)
	raw, _, err := mgr.Issue(sampleIssue())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Consume(raw, token.Binding{}); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	_, err = mgr.Consume(raw, token.Binding{})
	if !errors.Is(err, token.ErrReplay) {
		t.Fatalf("second consume error = %v, want ErrReplay", err)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	mgr := newTestManager(t, &now)

	raw, _, err := mgr.Issue(sampleIssue(func(r *token.IssueRequest) {
		r.TTL = time.Minute
	}))
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(61 * time.Second)
	_, err = mgr.Consume(raw, token.Binding{})
	if !errors.Is(err, token.ErrExpired) {
		t.Fatalf("Consume after expiry error = %v, want ErrExpired", err)
	}

	// An expired token must not be marked consumed; it stays invalid.
	if _, err := mgr.Consume(raw, token.Binding{}); !errors.Is(err, token.ErrExpired) {
		t.Fatalf("retry expired error = %v, want ErrExpired", err)
	}
}

func TestBindingMismatches(t *testing.T) {
	mgr := newTestManager(t, nil)
	raw, _, err := mgr.Issue(sampleIssue())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]token.Binding{
		"wrong file":    {File: "secret/other.pdf"},
		"wrong version": {Version: "v99"},
		"wrong user":    {User: "mallory@example.com"},
		"wrong purpose": {Purpose: token.PurposeDownload},
	}
	for name, bind := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := mgr.Consume(raw, bind)
			if !errors.Is(err, token.ErrBinding) {
				t.Fatalf("error = %v, want ErrBinding", err)
			}
		})
	}

	// A failed binding check must not consume the token: the correct context
	// still succeeds exactly once.
	if _, err := mgr.Consume(raw, token.Binding{File: "design/homepage-v3.fig"}); err != nil {
		t.Fatalf("valid consume after mismatches: %v", err)
	}
	if _, err := mgr.Consume(raw, token.Binding{}); !errors.Is(err, token.ErrReplay) {
		t.Fatalf("replay after successful consume = %v, want ErrReplay", err)
	}
}

func TestTamperedAndMalformedTokens(t *testing.T) {
	mgr := newTestManager(t, nil)
	raw, _, err := mgr.Issue(sampleIssue())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"empty":          "",
		"garbage":        "not-a-token",
		"too many parts": "a.b.c.d",
		"bad b64":        "@@@.###",
		"flipped sig":    flipSignatureHead(raw),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := mgr.Consume(bad, token.Binding{}); !errors.Is(err, token.ErrInvalidToken) {
				t.Fatalf("Consume(%q) error = %v, want ErrInvalidToken", name, err)
			}
		})
	}

	// Tampering with the payload segment must fail signature verification.
	parts := splitDots(raw)
	if len(parts) != 3 {
		t.Fatalf("issued token should have 3 parts, got %d", len(parts))
	}
	tampered := "pt1." + flipB64Char(parts[1]) + "." + parts[2]
	if _, err := mgr.Consume(tampered, token.Binding{}); !errors.Is(err, token.ErrInvalidToken) {
		t.Fatalf("tampered token error = %v, want ErrInvalidToken", err)
	}
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func flipB64Char(s string) string {
	b := []byte(s)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func flipSignatureHead(s string) string {
	dot := strings.LastIndex(s, ".")
	if dot < 0 || dot+1 >= len(s) {
		return s + "AA"
	}
	b := []byte(s)
	head := dot + 1
	if b[head] == 'A' {
		b[head] = 'B'
	} else {
		b[head] = 'A'
	}
	return string(b)
}

func TestIssueRejectsMissingBindings(t *testing.T) {
	mgr := newTestManager(t, nil)
	if _, _, err := mgr.Issue(token.IssueRequest{File: "f"}); !errors.Is(err, token.ErrInvalidRequest) {
		t.Fatalf("Issue with missing fields error = %v, want ErrInvalidRequest", err)
	}
}
