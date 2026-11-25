package enroll_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"certgateway/clock"
	"certgateway/enroll"
	"certgateway/identity"
	"certgateway/invitation"
	"certgateway/pki"
)

type harness struct {
	t     *testing.T
	svc   *enroll.Service
	store *invitation.Store
	ca    *pki.CA
	clock *clock.Clock
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clk := clock.NewAt(time.Now())
	store := invitation.NewStore()
	store.NowFunc = clk.Now
	ca, err := pki.NewRootCA("test-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, svc: enroll.NewService(store, ca), store: store, ca: ca, clock: clk}
}

func (h *harness) newInvitation(service, purpose string, ttl time.Duration) string {
	h.t.Helper()
	_, token, err := h.store.Create(invitation.CreateInput{
		Service: service, Purpose: purpose, InviteTTL: ttl, CertValidity: 2 * time.Hour,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return token
}

// solveChallenge performs Begin and returns the challenge id and valid signature.
func (h *harness) solveChallenge(token string) (challengeID string, signature []byte) {
	h.t.Helper()
	key, err := enroll.GenerateKey()
	if err != nil {
		h.t.Fatal(err)
	}
	csrDER, csrPEM, err := enroll.CreateCSRPEM(key, "")
	if err != nil {
		h.t.Fatal(err)
	}
	begin, err := h.svc.Begin(token, csrPEM)
	if err != nil {
		h.t.Fatalf("Begin: %v", err)
	}
	sig, err := enroll.SignChallenge(key, enroll.ChallengeTranscript(begin.Nonce, csrDER))
	if err != nil {
		h.t.Fatal(err)
	}
	return begin.ChallengeID, sig
}

func TestEnrollHappyPath(t *testing.T) {
	h := newHarness(t)
	token := h.newInvitation("billing.internal", identity.PurposeMetrics, time.Hour)
	challengeID, sig := h.solveChallenge(token)

	cred, err := h.svc.Complete(challengeID, sig)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if cred.Binding.Service != "billing.internal" || cred.Binding.Purpose != identity.PurposeMetrics {
		t.Fatalf("unexpected binding: %+v", cred.Binding)
	}

	block := decodeCert(t, cred.CertificatePEM)
	cert, err := parseCert(block)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ca.VerifyClientCert(cert, time.Now()); err != nil {
		t.Fatalf("issued cert does not verify: %v", err)
	}
	got, err := identity.Check(cert, "billing.internal", identity.PurposeMetrics)
	if err != nil {
		t.Fatalf("identity check: %v", err)
	}
	if got.InvitationID == "" {
		t.Fatal("binding missing invitation id")
	}
	if cred.Serial != cert.SerialNumber.String() {
		t.Fatalf("credential serial %q != certificate serial %s", cred.Serial, cert.SerialNumber)
	}
	stored, err := h.store.Get(got.InvitationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != invitation.StateConsumed || stored.CertSerial != cert.SerialNumber.String() {
		t.Fatalf("invitation audit record mismatch: state=%s serial=%q", stored.State, stored.CertSerial)
	}
}

func TestCompleteRejectsBadSignature(t *testing.T) {
	h := newHarness(t)
	token := h.newInvitation("billing.internal", identity.PurposeAPI, time.Hour)
	challengeID, _ := h.solveChallenge(token)

	if _, err := h.svc.Complete(challengeID, []byte("not-a-signature")); !errors.Is(err, enroll.ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
	// The failed completion consumes the challenge; replay must not work.
	if _, err := h.svc.Complete(challengeID, []byte("also-bad")); !errors.Is(err, enroll.ErrChallengeUsed) {
		t.Fatalf("want ErrChallengeUsed on replay, got %v", err)
	}
}

func TestInvitationCannotIssueTwice(t *testing.T) {
	h := newHarness(t)
	token := h.newInvitation("billing.internal", identity.PurposeAPI, time.Hour)

	id1, sig1 := h.solveChallenge(token)
	if _, err := h.svc.Complete(id1, sig1); err != nil {
		t.Fatalf("first issuance: %v", err)
	}

	// Token no longer authenticates, so a second Begin is impossible.
	if _, err := h.svc.Begin(token, mustCSRPEM(t)); !errors.Is(err, invitation.ErrUsed) {
		t.Fatalf("second Begin want ErrUsed, got %v", err)
	}
}

func TestExpiredInvitationCannotIssue(t *testing.T) {
	h := newHarness(t)
	token := h.newInvitation("billing.internal", identity.PurposeAPI, time.Minute)
	id, sig := h.solveChallenge(token)

	h.clock.Advance(2 * time.Minute)
	if _, err := h.svc.Complete(id, sig); !errors.Is(err, invitation.ErrExpired) {
		t.Fatalf("Complete after invite expiry want ErrExpired, got %v", err)
	}
	if _, err := h.store.Consume("whatever", "s"); err == nil {
		// sanity: unrelated id must not exist
		t.Fatal("expected not found for arbitrary id")
	}
}

func TestExpiredChallengeRejected(t *testing.T) {
	h := newHarness(t)
	h.svc.ChallengeTTL = time.Minute
	token := h.newInvitation("billing.internal", identity.PurposeAPI, time.Hour)
	id, sig := h.solveChallenge(token)

	h.clock.Advance(2 * time.Minute)
	if _, err := h.svc.Complete(id, sig); !errors.Is(err, enroll.ErrChallengeNotFound) {
		t.Fatalf("want ErrChallengeNotFound, got %v", err)
	}
}

func TestConcurrentCompletesIssueExactlyOneCertificate(t *testing.T) {
	h := newHarness(t)
	token := h.newInvitation("billing.internal", identity.PurposeAPI, time.Hour)

	const n = 16
	ids := make([]string, n)
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		ids[i], sigs[i] = h.solveChallenge(token)
	}

	var wg sync.WaitGroup
	results := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := h.svc.Complete(ids[i], sigs[i])
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	success, used := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, invitation.ErrUsed):
			used++
		default:
			t.Fatalf("unexpected Complete error: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly one issued certificate, got %d", success)
	}
	if used != n-1 {
		t.Fatalf("expected %d ErrUsed losers, got %d", n-1, used)
	}
}

func mustCSRPEM(t *testing.T) []byte {
	t.Helper()
	key, err := enroll.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, pem, err := enroll.CreateCSRPEM(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem
}
