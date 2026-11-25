package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certgateway/internal/gateway"
)

func TestFixtureInventoryAndStaleDetection(t *testing.T) {
	service, gatewayState := fixtureService(t)
	response := service.List(Filter{Preset: "all"})

	if response.Summary.Total != 5 {
		t.Fatalf("expected 5 certificates, got %d", response.Summary.Total)
	}
	if response.Summary.Active != 3 {
		t.Errorf("expected 3 active certificates, got %d", response.Summary.Active)
	}
	if response.Summary.Expired != 1 {
		t.Errorf("expected 1 expired certificate, got %d", response.Summary.Expired)
	}
	if response.Summary.Inconsistent != 1 {
		t.Errorf("expected 1 stale certificate, got %d", response.Summary.Inconsistent)
	}
	if response.Summary.Incomplete != 1 {
		t.Errorf("expected 1 incomplete chain, got %d", response.Summary.Incomplete)
	}

	byID := certificatesByID(response.Certificates)
	if got := byID["shop"].Chain.Status; got != ChainComplete {
		t.Errorf("shop chain = %q, want %q", got, ChainComplete)
	}
	if got := byID["admin"].Chain.Status; got != ChainMissingIntermediate {
		t.Errorf("admin chain = %q, want %q", got, ChainMissingIntermediate)
	}
	if got := byID["legacy"].Usage.State; got != UsageStandby {
		t.Errorf("legacy usage = %q, want %q", got, UsageStandby)
	}
	if got := byID["orders"].Usage.State; got != UsageStale {
		t.Errorf("orders usage = %q, want %q", got, UsageStale)
	}
	if byID["orders"].Usage.LoadedExpiresAt == "" {
		t.Error("stale certificate should expose the in-memory certificate expiry")
	}

	expiring := service.List(Filter{Preset: "30d"})
	if expiring.Visible != 1 || expiring.Certificates[0].ID != "admin" {
		t.Fatalf("30d filter returned %d certificates: %#v", expiring.Visible, expiring.Certificates)
	}

	dateRange := service.List(Filter{Preset: "custom", ExpiresAfter: "2027-01-01", ExpiresBefore: "2027-12-31"})
	if dateRange.Visible != 3 {
		t.Errorf("custom date filter returned %d certificates, want 3", dateRange.Visible)
	}

	if err := gatewayState.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	reloaded := service.List(Filter{Usage: UsageStale})
	if reloaded.Visible != 0 {
		t.Errorf("stale certificates after reload = %d, want 0", reloaded.Visible)
	}
}

func TestReloadPersistsCleanSnapshot(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "state.json")
	gatewayState, err := gateway.New(filepath.Join(root, "fixtures/gateway/gateway.json"), statePath, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := gatewayState.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("reload did not persist a snapshot: %v", err)
	}
	service := NewService(gatewayState).WithClock(fixedClock)
	response := service.List(Filter{Preset: "all"})
	if response.Summary.Inconsistent != 0 {
		t.Fatalf("expected a clean snapshot, got %d stale certificates", response.Summary.Inconsistent)
	}
}

func fixtureService(t *testing.T) (*Service, *gateway.Gateway) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "fixtures/gateway/state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot gateway.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	orders := snapshot.Certificates["orders"]
	orders.Fingerprint = strings.Repeat("0", 64)
	orders.BundleSHA256 = strings.Repeat("0", 64)
	snapshot.Certificates["orders"] = orders
	data, err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	gatewayState, err := gateway.New(filepath.Join(root, "fixtures/gateway/gateway.json"), statePath, root)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(gatewayState).WithClock(fixedClock), gatewayState
}

func certificatesByID(certificates []Certificate) map[string]Certificate {
	result := make(map[string]Certificate, len(certificates))
	for _, cert := range certificates {
		result[cert.ID] = cert
	}
	return result
}

func fixedClock() time.Time {
	return time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
}
