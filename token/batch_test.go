package token_test

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"previewtoken/token"
)

func TestConcurrentConsumeOnlyOneWins(t *testing.T) {
	mgr := newTestManager(t, nil)
	raw, _, err := mgr.Issue(sampleIssue())
	if err != nil {
		t.Fatal(err)
	}

	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, replays := 0, 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := mgr.Consume(raw, token.Binding{})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			case errors.Is(err, token.ErrReplay):
				replays++
			default:
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wg.Wait()

	if success != 1 {
		t.Fatalf("successful consumes = %d, want 1", success)
	}
	if replays != n-1 {
		t.Fatalf("rejected replays = %d, want %d", replays, n-1)
	}
}

func TestIssueBatchDistinctTokensAllSucceed(t *testing.T) {
	mgr := newTestManager(t, nil)
	items := []string{"w64", "w128", "w256", "w512"}
	batch, err := mgr.IssueBatch(token.BatchRequest{
		File: "photos/team.png", Version: "v1", User: "bob",
		Items: items,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Tokens) != len(items) {
		t.Fatalf("got %d tokens, want %d", len(batch.Tokens), len(items))
	}

	// Tokens must be unique and share one batch id.
	seen := map[string]bool{}
	for i, c := range batch.Claims {
		if seen[batch.Tokens[i]] {
			t.Fatal("duplicate token in batch")
		}
		seen[batch.Tokens[i]] = true
		if c.BatchID != batch.BatchID || c.Item != items[i] {
			t.Fatalf("claim %d not grouped/scoped: %+v", i, c)
		}
	}

	// Simulate the same page firing all thumbnail requests at once.
	var wg sync.WaitGroup
	errs := make(chan error, len(batch.Tokens))
	wg.Add(len(batch.Tokens))
	for i, raw := range batch.Tokens {
		raw, item := raw, items[i]
		go func() {
			defer wg.Done()
			_, err := mgr.Consume(raw, token.Binding{Item: item})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("batch thumbnail request was misjudged as replay: %v", err)
		}
	}

	// Every individual token is still one-time: replaying any fails.
	for _, raw := range batch.Tokens {
		if _, err := mgr.Consume(raw, token.Binding{}); !errors.Is(err, token.ErrReplay) {
			t.Fatalf("batch token replay error = %v, want ErrReplay", err)
		}
	}
}

func TestPageSessionBatchGrant(t *testing.T) {
	now := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	mgr := newTestManager(t, &now)
	items := []string{"thumb-0", "thumb-1", "thumb-2"}

	rawPage, pageClaims, err := mgr.Issue(sampleIssue(func(r *token.IssueRequest) {
		r.Purpose = token.PurposePage
		r.Items = items
		r.TTL = 5 * time.Minute
	}))
	if err != nil {
		t.Fatal(err)
	}
	if pageClaims.JTI == "" {
		t.Fatal("missing jti")
	}

	grant, claims, err := mgr.OpenSession(rawPage)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if claims.Kind != token.KindBatch || claims.MaxUses != len(items) {
		t.Fatalf("unexpected grant claims: %+v", claims)
	}

	// The page token is one-time: a second exchange is a replay.
	if _, _, err := mgr.OpenSession(rawPage); !errors.Is(err, token.ErrReplay) {
		t.Fatalf("second OpenSession error = %v, want ErrReplay", err)
	}

	// Concurrent distinct items all succeed.
	var wg sync.WaitGroup
	errs := make(chan error, len(items))
	for _, item := range items {
		wg.Add(1)
		go func(item string) {
			defer wg.Done()
			_, err := mgr.Consume(grant, token.Binding{
				Purpose: token.PurposeThumbnail, Item: item,
			})
			errs <- err
		}(item)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("distinct batch item rejected: %v", err)
		}
	}

	// Repeating an item is a genuine replay.
	_, err = mgr.Consume(grant, token.Binding{Item: items[0]})
	if !errors.Is(err, token.ErrReplay) {
		t.Fatalf("duplicate item error = %v, want ErrReplay", err)
	}
	// An item outside the allow list is rejected.
	_, err = mgr.Consume(grant, token.Binding{Item: "thumb-evil"})
	if !errors.Is(err, token.ErrItemNotAllowed) {
		t.Fatalf("unknown item error = %v, want ErrItemNotAllowed", err)
	}
	// Missing item selector is rejected.
	_, err = mgr.Consume(grant, token.Binding{})
	if !errors.Is(err, token.ErrItemRequired) {
		t.Fatalf("missing item error = %v, want ErrItemRequired", err)
	}
}

func TestJSONStorePersistenceAcrossManagers(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "nested", "tokens.json")
	secret := []byte("persistence-secret-0123456789abcd")
	store := token.NewJSONStore(path)

	mgr1, err := token.NewManager(secret, store, token.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := mgr1.Issue(sampleIssue())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr1.Consume(raw, token.Binding{}); err != nil {
		t.Fatal(err)
	}

	// A brand new manager (simulating a process restart) reloads the JSON
	// ledger: the consumed token must stay consumed.
	mgr2, err := token.NewManager(secret, token.NewJSONStore(path),
		token.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr2.Consume(raw, token.Binding{}); !errors.Is(err, token.ErrReplay) {
		t.Fatalf("replay after restart error = %v, want ErrReplay", err)
	}

	// The same HMAC secret still validates newly issued tokens.
	raw2, _, err := mgr2.Issue(sampleIssue(func(r *token.IssueRequest) {
		r.User = "carol"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr2.Consume(raw2, token.Binding{User: "carol"}); err != nil {
		t.Fatalf("new token after restart: %v", err)
	}
}
