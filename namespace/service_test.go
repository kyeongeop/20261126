package namespace

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeClock struct {
	now time.Time
}

func (f *fakeClock) Now() time.Time { return f.now }

func (f *fakeClock) Advance(d time.Duration) { f.now = f.now.Add(d) }

func testService(t *testing.T, now time.Time) (*Service, *Store, *fakeClock) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "seed.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	store, err := NewStore(state, "")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	clock := &fakeClock{now: now}
	return NewService(store, clock), store, clock
}

func login(t *testing.T, service *Service, token string) User {
	t.Helper()
	user, err := service.Authenticate(token)
	if err != nil {
		t.Fatalf("authenticate %s: %v", token, err)
	}
	return user
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got nil", code)
	}
	apiErr := asError(err)
	if apiErr.Code != code {
		t.Fatalf("expected code %s, got %s (%v)", code, apiErr.Code, err)
	}
}

func TestClaimApprovalReservationAndTransferAudit(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	service, store, clock := testService(t, now)
	bob := login(t, service, "bob-demo-token")
	admin := login(t, service, "admin-demo-token")
	carol := login(t, service, "carol-demo-token")

	claim, err := service.CreateClaim(bob, CreateClaimRequest{
		Namespace: "new-team",
		Reason:    "new service team needs a package namespace",
	}, RequestMeta{RequestID: "req-claim", RemoteAddr: "127.0.0.1:4000"})
	if err != nil {
		t.Fatalf("create claim: %v", err)
	}
	if claim.Status != ClaimPending {
		t.Fatalf("claim status = %s", claim.Status)
	}
	if !claim.HoldUntil.Equal(now.Add(72 * time.Hour)) {
		t.Fatalf("hold until = %s", claim.HoldUntil)
	}

	approved, err := service.ApproveClaim(admin, claim.ID, ApproveClaimRequest{ReservationDays: 30}, RequestMeta{RequestID: "req-approve"})
	if err != nil {
		t.Fatalf("approve claim: %v", err)
	}
	if approved.Status != ClaimApproved {
		t.Fatalf("approved status = %s", approved.Status)
	}
	if !approved.ReservedUntil.Equal(now.Add(30 * 24 * time.Hour)) {
		t.Fatalf("reserved until = %s", approved.ReservedUntil)
	}
	view, err := service.GetNamespace("new-team")
	if err != nil {
		t.Fatalf("get namespace: %v", err)
	}
	if view.OwnerID != bob.ID || view.State != NamespaceReserved || !view.ReservationActive {
		t.Fatalf("unexpected namespace view: %+v", view)
	}

	clock.Advance(2 * time.Hour)
	renewed, err := service.Renew(bob, "new-team", RenewRequest{ReservationDays: 30, Reason: "extend launch window"}, RequestMeta{RequestID: "req-renew"})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !renewed.ReservedUntil.Equal(now.Add(60 * 24 * time.Hour)) {
		t.Fatalf("renewed until = %s", renewed.ReservedUntil)
	}

	transferred, err := service.Transfer(bob, "new-team", TransferRequest{
		ToUserID:        carol.ID,
		ReservationDays: 45,
		Reason:          "team ownership handoff",
	}, RequestMeta{RequestID: "req-transfer", RemoteAddr: "127.0.0.1:4000"})
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if transferred.OwnerID != carol.ID || transferred.OwnerName != carol.Name {
		t.Fatalf("transfer target = %+v", transferred.Namespace)
	}

	audit := store.Snapshot().Audit
	var transfer AuditEvent
	for _, event := range audit {
		if event.Type == AuditOwnershipTransferred {
			transfer = event
		}
	}
	if transfer.FromOwnerID != bob.ID || transfer.ToOwnerID != carol.ID {
		t.Fatalf("transfer audit owners = %q -> %q", transfer.FromOwnerID, transfer.ToOwnerID)
	}
	if transfer.Reason != "team ownership handoff" || transfer.RequestID != "req-transfer" {
		t.Fatalf("transfer audit context missing: %+v", transfer)
	}
	if err := verifyAuditChain(audit); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
	if _, err := service.Publish(carol, PublishRequest{Namespace: "new-team", Name: "svc", Version: "1.0.0"}, RequestMeta{}); err != nil {
		t.Fatalf("new owner publish: %v", err)
	}
	if _, err := service.Publish(bob, PublishRequest{Namespace: "new-team", Name: "svc", Version: "1.0.1"}, RequestMeta{}); err == nil {
		t.Fatal("former owner published after transfer")
	}
}

func TestPackageNamespaceCannotBeClaimedOrObtainedByPublishing(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	service, store, _ := testService(t, now)
	bob := login(t, service, "bob-demo-token")
	admin := login(t, service, "admin-demo-token")

	_, err := service.CreateClaim(bob, CreateClaimRequest{Namespace: "legacy-tools", Reason: "looks abandoned"}, RequestMeta{})
	requireCode(t, err, "namespace_has_packages")

	_, err = service.Publish(bob, PublishRequest{Namespace: "legacy-tools", Name: "intruder", Version: "9.9.9"}, RequestMeta{})
	requireCode(t, err, "namespace_not_owned")

	transferred, err := service.Transfer(admin, "legacy-tools", TransferRequest{
		ToUserID:        bob.ID,
		ReservationDays: 90,
		Reason:          "approved legacy ownership transfer",
	}, RequestMeta{RequestID: "req-legacy"})
	if err != nil {
		t.Fatalf("admin transfer legacy namespace: %v", err)
	}
	if transferred.OwnerID != bob.ID {
		t.Fatalf("legacy transfer owner = %s", transferred.OwnerID)
	}
	if _, err := service.Publish(bob, PublishRequest{Namespace: "legacy-tools", Name: "approved", Version: "1.0.0"}, RequestMeta{}); err != nil {
		t.Fatalf("publish after approved transfer: %v", err)
	}
	events := store.Snapshot().Audit
	if len(events) < 2 {
		t.Fatalf("expected transfer and publish audit, got %d events", len(events))
	}
	if err := verifyAuditChain(events); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

func TestReservationExpiryReleasesOnlyEmptyNamespaces(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	service, store, clock := testService(t, now)
	bob := login(t, service, "bob-demo-token")
	admin := login(t, service, "admin-demo-token")
	carol := login(t, service, "carol-demo-token")

	claim, err := service.CreateClaim(bob, CreateClaimRequest{Namespace: "short-lived", Reason: "temporary ownership"}, RequestMeta{})
	if err != nil {
		t.Fatalf("create claim: %v", err)
	}
	if _, err := service.ApproveClaim(admin, claim.ID, ApproveClaimRequest{ReservationDays: 1}, RequestMeta{}); err != nil {
		t.Fatalf("approve claim: %v", err)
	}
	clock.Advance(48 * time.Hour)
	newClaim, err := service.CreateClaim(carol, CreateClaimRequest{Namespace: "short-lived", Reason: "take over expired reservation"}, RequestMeta{})
	if err != nil {
		t.Fatalf("claim expired namespace: %v", err)
	}
	if newClaim.Status != ClaimPending {
		t.Fatalf("new claim status = %s", newClaim.Status)
	}

	clock.now = time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = service.CreateClaim(carol, CreateClaimRequest{Namespace: "team-alpha", Reason: "package namespace should stay protected"}, RequestMeta{})
	requireCode(t, err, "namespace_has_packages")
	view, err := service.GetNamespace("team-alpha")
	if err != nil {
		t.Fatalf("get package namespace: %v", err)
	}
	if view.OwnerID != "alice" || view.State != NamespaceReserved || !view.ReservationExpired {
		t.Fatalf("package namespace ownership changed: %+v", view)
	}
	if view.Available {
		t.Fatal("package namespace reported available")
	}
	events := store.Snapshot().Audit
	foundExpiry := false
	for _, event := range events {
		if event.Type == AuditReservationExpired && event.Namespace == "short-lived" {
			foundExpiry = true
		}
		if event.Type == AuditReservationExpired && event.Namespace == "team-alpha" {
			t.Fatal("package namespace reservation was released")
		}
	}
	if !foundExpiry {
		t.Fatal("empty namespace expiry was not audited")
	}
}

func TestAuditTarExportAndTamperDetection(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	service, store, _ := testService(t, now)
	bob := login(t, service, "bob-demo-token")
	admin := login(t, service, "admin-demo-token")
	claim, err := service.CreateClaim(bob, CreateClaimRequest{Namespace: "audit-team", Reason: "audit"}, RequestMeta{})
	if err != nil {
		t.Fatalf("create claim: %v", err)
	}
	if _, err := service.ApproveClaim(admin, claim.ID, ApproveClaimRequest{}, RequestMeta{}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	events := store.Snapshot().Audit

	var buf bytes.Buffer
	if err := WriteAuditTar(&buf, events, now); err != nil {
		t.Fatalf("write audit tar: %v", err)
	}
	files := readTar(t, buf.Bytes())
	for _, name := range []string{"audit/README.txt", "audit/manifest.json", "audit/index.jsonl"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("missing tar entry %s", name)
		}
	}
	var manifest auditManifest
	if err := json.Unmarshal(files["audit/manifest.json"], &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.EventCount != len(events) || !manifest.ChainValid || manifest.HashAlgorithm != "sha256" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if !VerifyAudit(events, now).Valid {
		t.Fatal("audit verification failed")
	}

	tampered := append([]AuditEvent(nil), events...)
	tampered[0].Reason = "forged"
	if err := verifyAuditChain(tampered); err == nil {
		t.Fatal("tampered audit chain still verified")
	}
}

func readTar(t *testing.T, payload []byte) map[string][]byte {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(payload))
	files := make(map[string][]byte)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read tar entry %s: %v", header.Name, err)
		}
		files[header.Name] = content
	}
	return files
}

func TestStatePersistsAuditAcrossReopen(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state.json")
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "seed.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	store, err := NewStore(state, statePath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	service := NewService(store, &fakeClock{now: now})
	admin := login(t, service, "admin-demo-token")
	transfer, err := service.Transfer(admin, "legacy-tools", TransferRequest{ToUserID: "bob", Reason: "migration"}, RequestMeta{RequestID: "persist"})
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if transfer.OwnerID != "bob" {
		t.Fatalf("owner = %s", transfer.OwnerID)
	}
	reopened, err := OpenStore(statePath, filepath.Join("..", "fixtures", "seed.json"))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	audit := reopened.Snapshot().Audit
	if err := verifyAuditChain(audit); err != nil {
		t.Fatalf("reopened audit chain: %v", err)
	}
	if len(audit) == 0 || audit[len(audit)-1].Type != AuditOwnershipTransferred {
		t.Fatalf("transfer audit not persisted: %+v", audit)
	}
}

func TestTokenHashFixture(t *testing.T) {
	sum := sha256.Sum256([]byte("alice-demo-token"))
	if got := hex.EncodeToString(sum[:]); got != "bba775a1794a2ccaa524798e32cea98187c9a32d80433d760a92d449bfddff66" {
		t.Fatalf("token fixture hash changed: %s", got)
	}
}

func TestPendingClaimLimitPreventsBulkSquatting(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	service, _, _ := testService(t, now)
	bob := login(t, service, "bob-demo-token")
	for _, name := range []string{"limit-one", "limit-two", "limit-three"} {
		if _, err := service.CreateClaim(bob, CreateClaimRequest{Namespace: name, Reason: "pending limit test"}, RequestMeta{}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	_, err := service.CreateClaim(bob, CreateClaimRequest{Namespace: "limit-four", Reason: "should be limited"}, RequestMeta{})
	requireCode(t, err, "claim_limit_reached")
}

func TestNamespaceHistoryAllowsFormerOwner(t *testing.T) {
	now := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	service, _, _ := testService(t, now)
	bob := login(t, service, "bob-demo-token")
	admin := login(t, service, "admin-demo-token")
	carol := login(t, service, "carol-demo-token")
	claim, err := service.CreateClaim(bob, CreateClaimRequest{Namespace: "history-team", Reason: "history"}, RequestMeta{})
	if err != nil {
		t.Fatalf("create claim: %v", err)
	}
	if _, err := service.ApproveClaim(admin, claim.ID, ApproveClaimRequest{}, RequestMeta{}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := service.Transfer(bob, "history-team", TransferRequest{ToUserID: carol.ID, Reason: "handoff"}, RequestMeta{}); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	events, err := service.NamespaceAudit(bob, "history-team")
	if err != nil {
		t.Fatalf("former owner history: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("former owner received no history")
	}
	events, err = service.NamespaceAudit(carol, "history-team")
	if err != nil {
		t.Fatalf("current owner history: %v", err)
	}
	foundTransfer := false
	for _, event := range events {
		if event.Type == AuditOwnershipTransferred {
			foundTransfer = true
		}
	}
	if !foundTransfer {
		t.Fatal("current owner history has no transfer event")
	}
}
