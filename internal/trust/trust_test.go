package trust

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

type testChain struct {
	rootKey  ed25519.PrivateKey
	root     *Certificate
	caKey    ed25519.PrivateKey
	ca       *Certificate
	leafKey  ed25519.PrivateKey
	leaf     *Certificate
	now      time.Time
	manifest []byte
	envelope []byte
}

func buildTestChain(t *testing.T) *testChain {
	t.Helper()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	rootKF, rootKey, err := GenerateKey("root-ca")
	if err != nil {
		t.Fatal(err)
	}
	_ = rootKF
	root, err := NewRoot("root-ca", 1, rootKey, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	_, caKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := IssueCert("intermediate-ca", 2, true, now, now.Add(time.Hour), root, rootKey, caKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	_, leafKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := IssueCert("mirror-signer", 3, false, now, now.Add(time.Hour), ca, caKey, leafKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	manifest := []byte(`{"imageId":"img-1"}`)
	env, err := SignManifest(manifest, leafKey, leaf, []*Certificate{ca, root})
	if err != nil {
		t.Fatal(err)
	}
	envBytes, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &testChain{
		rootKey: rootKey, root: root, caKey: caKey, ca: ca,
		leafKey: leafKey, leaf: leaf, now: now,
		manifest: manifest, envelope: envBytes,
	}
}

func TestFullChainVerifies(t *testing.T) {
	tc := buildTestChain(t)
	if err := VerifyEnvelope(tc.manifest, tc.envelope, tc.root, tc.now); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

func TestTamperedManifestRejected(t *testing.T) {
	tc := buildTestChain(t)
	tampered := []byte(`{"imageId":"img-evil"}`)
	if err := VerifyEnvelope(tampered, tc.envelope, tc.root, tc.now); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestExpiredCertificateRejected(t *testing.T) {
	tc := buildTestChain(t)
	err := VerifyEnvelope(tc.manifest, tc.envelope, tc.root, tc.now.Add(2*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}
}

func TestUntrustedRootRejected(t *testing.T) {
	tc := buildTestChain(t)
	_, otherKey, err := GenerateKey("other-root")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewRoot("other-root", 9, otherKey, tc.now, tc.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelope(tc.manifest, tc.envelope, other, tc.now); err == nil {
		t.Fatal("envelope verified under an unrelated trust root")
	}
}

func TestForgedLeafSignatureRejected(t *testing.T) {
	tc := buildTestChain(t)
	_, forgerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign with a key the certificate does not hold.
	env, err := ParseEnvelope(tc.envelope)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = b64(ed25519.Sign(forgerKey, tc.manifest))
	forged, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelope(tc.manifest, forged, tc.root, tc.now); err == nil {
		t.Fatal("forged manifest signature accepted")
	}
}

func TestRootMustBeCA(t *testing.T) {
	tc := buildTestChain(t)
	fakeRoot := *tc.root
	fakeRoot.IsCA = false
	if err := VerifyEnvelope(tc.manifest, tc.envelope, &fakeRoot, tc.now); err == nil {
		t.Fatal("non-CA root accepted")
	}
}
