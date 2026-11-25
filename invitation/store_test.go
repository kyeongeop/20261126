package invitation_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"certgateway/clock"
	"certgateway/identity"
	"certgateway/invitation"
)

func newTestStore(t *testing.T) (*invitation.Store, *clock.Clock) {
	t.Helper()
	clk := clock.NewAt(time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC))
	store := invitation.NewStore()
	store.NowFunc = clk.Now
	return store, clk
}

func TestCreateAndAuthenticate(t *testing.T) {
	store, _ := newTestStore(t)
	inv, token, err := store.Create(invitation.CreateInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI,
		InviteTTL: time.Minute, CertValidity: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || inv.ID == "" {
		t.Fatal("expected non-empty token and id")
	}

	got, err := store.AuthenticateToken(token)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if got.ID != inv.ID || got.Service != "billing.internal" || got.Purpose != identity.PurposeAPI {
		t.Fatalf("unexpected invitation: %+v", got)
	}

	if _, err := store.AuthenticateToken("not-the-token"); !errors.Is(err, invitation.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for bogus token, got %v", err)
	}
}

func TestCreateRejectsInvalidInput(t *testing.T) {
	store, _ := newTestStore(t)
	if _, _, err := store.Create(invitation.CreateInput{Purpose: identity.PurposeAPI}); !errors.Is(err, invitation.ErrInvalidService) {
		t.Fatalf("want ErrInvalidService, got %v", err)
	}
	if _, _, err := store.Create(invitation.CreateInput{Service: "s", Purpose: "nope"}); !errors.Is(err, invitation.ErrInvalidPurpose) {
		t.Fatalf("want ErrInvalidPurpose, got %v", err)
	}
	if _, _, err := store.Create(invitation.CreateInput{Service: "s", Purpose: identity.PurposeAPI, InviteTTL: -1}); !errors.Is(err, invitation.ErrInvalidTTL) {
		t.Fatalf("want ErrInvalidTTL, got %v", err)
	}
}

func TestInvitationCanBeConsumedOnlyOnce(t *testing.T) {
	store, _ := newTestStore(t)
	inv, token, err := store.Create(invitation.CreateInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI, InviteTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	consumed, err := store.Consume(inv.ID, "serial-1")
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if consumed.State != invitation.StateConsumed || consumed.CertSerial != "serial-1" || consumed.UsedAt.IsZero() {
		t.Fatalf("consumed invitation wrong: %+v", consumed)
	}

	if _, err := store.Consume(inv.ID, "serial-2"); !errors.Is(err, invitation.ErrUsed) {
		t.Fatalf("second Consume want ErrUsed, got %v", err)
	}
	if _, err := store.AuthenticateToken(token); !errors.Is(err, invitation.ErrUsed) {
		t.Fatalf("token after consumption want ErrUsed, got %v", err)
	}
}

func TestExpiredInvitationCannotBeConsumed(t *testing.T) {
	store, clk := newTestStore(t)
	inv, token, err := store.Create(invitation.CreateInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI, InviteTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	clk.Advance(90 * time.Second)

	if _, err := store.AuthenticateToken(token); !errors.Is(err, invitation.ErrExpired) {
		t.Fatalf("authenticate expired want ErrExpired, got %v", err)
	}
	if _, err := store.Consume(inv.ID, "serial-1"); !errors.Is(err, invitation.ErrExpired) {
		t.Fatalf("consume expired want ErrExpired, got %v", err)
	}

	got, _ := store.Get(inv.ID)
	if got.State != invitation.StateExpired {
		t.Fatalf("expected lazy expired state, got %s", got.State)
	}
}

func TestRevokedInvitationCannotBeConsumed(t *testing.T) {
	store, _ := newTestStore(t)
	inv, _, err := store.Create(invitation.CreateInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI, InviteTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(inv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(inv.ID, "s"); !errors.Is(err, invitation.ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

func TestConcurrentConsumeHasSingleWinner(t *testing.T) {
	store, _ := newTestStore(t)
	inv, _, err := store.Create(invitation.CreateInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI, InviteTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	const n = 64
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := store.Consume(inv.ID, "serial")
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)

	wins, used := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, invitation.ErrUsed):
			used++
		default:
			t.Fatalf("unexpected consume error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("expected exactly one winner, got %d", wins)
	}
	if used != n-1 {
		t.Fatalf("expected %d ErrUsed, got %d", n-1, used)
	}
}

func TestGetReturnsCopy(t *testing.T) {
	store, _ := newTestStore(t)
	inv, _, _ := store.Create(invitation.CreateInput{
		Service: "billing.internal", Purpose: identity.PurposeAPI, InviteTTL: time.Minute,
	})
	got, _ := store.Get(inv.ID)
	got.Service = "tampered"

	again, _ := store.Get(inv.ID)
	if again.Service != "billing.internal" {
		t.Fatal("store returned mutable pointer; expected defensive copy")
	}
}
