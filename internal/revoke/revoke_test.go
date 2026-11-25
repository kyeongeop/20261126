package revoke_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"offlinegw/internal/revoke"
	"offlinegw/internal/testutil"
)

var (
	now        = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	thisUpdate = now.Add(-time.Hour)
	nextUpdate = now.Add(time.Hour)
)

func verifierWithCRL(t *testing.T, serials []int64, this, next time.Time, policy revoke.StalePolicy) (*revoke.Verifier, *testutil.CA) {
	t.Helper()
	ca := testutil.NewCA(t, "test-ca")
	src := &revoke.Source{}
	crlDER := ca.CreateCRL(t, serials, this, next)
	crlFile := writeTemp(t, crlDER)
	if err := src.LoadCRLFile(crlFile, ca.Cert); err != nil {
		t.Fatal(err)
	}
	return &revoke.Verifier{Source: src, StalePolicy: policy, Now: func() time.Time { return now }}, ca
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := t.TempDir() + "/pinned.bin"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCRLGood(t *testing.T) {
	v, ca := verifierWithCRL(t, []int64{7}, thisUpdate, nextUpdate, revoke.StaleDeny)
	cert := testutil.Leaf(t, ca.Issue(t, "client-a", 8, false))
	d := v.Check(cert)
	if !d.Allowed || d.Degraded {
		t.Fatalf("expected allow, got %+v (%s)", d, d.Reason)
	}
	if d.Result.ThisUpdate != thisUpdate || d.Result.NextUpdate != nextUpdate {
		t.Fatalf("thisUpdate/nextUpdate not recorded: %+v", d.Result)
	}
	if !strings.Contains(d.Reason, "good") {
		t.Fatalf("reason missing status: %q", d.Reason)
	}
}

func TestCRLRevoked(t *testing.T) {
	v, ca := verifierWithCRL(t, []int64{7}, thisUpdate, nextUpdate, revoke.StaleDeny)
	cert := testutil.Leaf(t, ca.Issue(t, "client-b", 7, false))
	d := v.Check(cert)
	if d.Allowed {
		t.Fatalf("expected deny, got %+v", d)
	}
	if d.Result.Status != revoke.StatusRevoked {
		t.Fatalf("status = %v", d.Result.Status)
	}
	if !strings.Contains(d.Reason, "revoked") {
		t.Fatalf("reason missing cause: %q", d.Reason)
	}
}

func TestUnknownWithoutSource(t *testing.T) {
	ca := testutil.NewCA(t, "test-ca")
	v := &revoke.Verifier{Source: &revoke.Source{}, StalePolicy: revoke.StaleDeny, Now: func() time.Time { return now }}
	cert := testutil.Leaf(t, ca.Issue(t, "client-c", 9, false))
	d := v.Check(cert)
	if d.Allowed || d.Result.Status != revoke.StatusUnknown {
		t.Fatalf("expected unknown deny, got %+v", d)
	}
	if !strings.Contains(d.Reason, "no pinned CRL or OCSP") {
		t.Fatalf("reason missing cause: %q", d.Reason)
	}
}

func TestStalePolicies(t *testing.T) {
	expired := now.Add(-time.Minute)
	cases := []struct {
		name     string
		policy   revoke.StalePolicy
		allowed  bool
		degraded bool
	}{
		{"deny", revoke.StaleDeny, false, false},
		{"allow", revoke.StaleAllow, true, false},
		{"degrade", revoke.StaleDegrade, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ca := verifierWithCRL(t, nil, thisUpdate, expired, tc.policy)
			cert := testutil.Leaf(t, ca.Issue(t, "client-d", 11, false))
			d := v.Check(cert)
			if d.Allowed != tc.allowed || d.Degraded != tc.degraded {
				t.Fatalf("policy %s: got allowed=%v degraded=%v", tc.policy, d.Allowed, d.Degraded)
			}
			if !d.Result.Stale {
				t.Fatal("stale flag not recorded")
			}
			if !strings.Contains(d.Reason, "stale") || !strings.Contains(d.Reason, "stale-policy="+tc.name) {
				t.Fatalf("reason missing stale cause: %q", d.Reason)
			}
		})
	}
}

func TestOCSPStatuses(t *testing.T) {
	ca := testutil.NewCA(t, "test-ca")
	cases := []struct {
		name    string
		status  testutil.OCSPStatus
		allowed bool
	}{
		{"good", testutil.OCSPGood, true},
		{"revoked", testutil.OCSPRevoked, false},
		{"unknown", testutil.OCSPUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &revoke.Source{}
			der := ca.CreateOCSPResponse(t, 21, tc.status, thisUpdate, nextUpdate)
			if err := src.LoadOCSPFile(writeTemp(t, der), ca.Cert); err != nil {
				t.Fatal(err)
			}
			v := &revoke.Verifier{Source: src, StalePolicy: revoke.StaleDeny, Now: func() time.Time { return now }}
			cert := testutil.Leaf(t, ca.Issue(t, "client-e", 21, false))
			d := v.Check(cert)
			if d.Allowed != tc.allowed {
				t.Fatalf("ocsp %s: allowed=%v reason=%q", tc.name, d.Allowed, d.Reason)
			}
			if d.Result.Source != "ocsp" {
				t.Fatalf("source = %q", d.Result.Source)
			}
		})
	}
}

func TestOCSPStaleDegrade(t *testing.T) {
	ca := testutil.NewCA(t, "test-ca")
	src := &revoke.Source{}
	der := ca.CreateOCSPResponse(t, 22, testutil.OCSPGood, thisUpdate, now.Add(-time.Minute))
	if err := src.LoadOCSPFile(writeTemp(t, der), ca.Cert); err != nil {
		t.Fatal(err)
	}
	v := &revoke.Verifier{Source: src, StalePolicy: revoke.StaleDegrade, Now: func() time.Time { return now }}
	cert := testutil.Leaf(t, ca.Issue(t, "client-f", 22, false))
	d := v.Check(cert)
	if !d.Allowed || !d.Degraded {
		t.Fatalf("expected degraded allow, got %+v", d)
	}
}

func TestOCSPTamperedSignatureRejected(t *testing.T) {
	ca := testutil.NewCA(t, "test-ca")
	der := ca.CreateOCSPResponse(t, 23, testutil.OCSPGood, thisUpdate, nextUpdate)
	der[len(der)-10] ^= 0xff
	src := &revoke.Source{}
	if err := src.LoadOCSPFile(writeTemp(t, der), ca.Cert); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestAuditLogContainsReason(t *testing.T) {
	v, ca := verifierWithCRL(t, []int64{7}, thisUpdate, now.Add(-time.Minute), revoke.StaleDegrade)
	cert := testutil.Leaf(t, ca.Issue(t, "client-g", 8, false))
	d := v.Check(cert)
	var buf bytes.Buffer
	revoke.NewAuditLogger(&buf).Log("127.0.0.1:1234", cert, d, v.StalePolicy)
	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"time", "subject", "serial", "source", "status", "this_update", "next_update", "stale", "stale_policy", "decision", "reason"} {
		if _, ok := entry[key]; !ok {
			t.Fatalf("audit entry missing %q: %v", key, entry)
		}
	}
	if entry["decision"] != "degrade" {
		t.Fatalf("decision = %v", entry["decision"])
	}
	if !strings.Contains(entry["reason"].(string), "stale-policy=degrade") {
		t.Fatalf("reason = %v", entry["reason"])
	}
}
