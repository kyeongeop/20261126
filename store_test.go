package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for name, content := range files {
		header := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := io.WriteString(writer, content); err != nil {
			t.Fatalf("write tar entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buffer.Bytes()
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func publishBytes(store *Store, name, version string, artifact []byte, role string) (Release, error) {
	return store.Publish(PublishRequest{
		Name:     name,
		Version:  version,
		Artifact: bytes.NewReader(artifact),
		Publisher: Publisher{
			User:       "test-user",
			Role:       role,
			RemoteAddr: "127.0.0.1:1234",
		},
	})
}

func TestPublishDigestSignatureAndPublisher(t *testing.T) {
	store := newTestStore(t)
	artifact := testTar(t, map[string]string{"bin/tool": "version one\n"})
	release, err := publishBytes(store, "demo", "1.0.0", artifact, rolePublisher)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got, want := release.ContentDigest, digestBytes(artifact); got != want {
		t.Fatalf("digest = %q, want %q", got, want)
	}
	if release.Publisher.User != "test-user" || release.Publisher.Role != rolePublisher {
		t.Fatalf("publisher not recorded: %+v", release.Publisher)
	}
	if release.Signature.Algorithm != signatureAlgorithm || release.Signature.KeyID == "" {
		t.Fatalf("signature metadata missing: %+v", release.Signature)
	}
	if !store.Verify(release).Valid {
		t.Fatalf("fresh release should verify: %+v", store.Verify(release))
	}
	if release.Archive.Entries != 1 || release.Archive.Size != int64(len(artifact)) {
		t.Fatalf("archive metadata mismatch: %+v", release.Archive)
	}
}

func TestDuplicateReleaseCannotOverwrite(t *testing.T) {
	store := newTestStore(t)
	first := testTar(t, map[string]string{"README": "first"})
	second := testTar(t, map[string]string{"README": "second"})
	release, err := publishBytes(store, "demo", "1.0.0", first, rolePublisher)
	if err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if _, err := publishBytes(store, "demo", "1.0.0", second, rolePublisher); err != errVersionExists {
		t.Fatalf("duplicate error = %v, want %v", err, errVersionExists)
	}
	loaded, err := store.Release("demo", "1.0.0")
	if err != nil {
		t.Fatalf("load release: %v", err)
	}
	if loaded.ContentDigest != release.ContentDigest {
		t.Fatalf("duplicate upload changed published digest")
	}
}

func TestAdminRepairCreatesNewVersionAndKeepsOriginal(t *testing.T) {
	store := newTestStore(t)
	original := testTar(t, map[string]string{"install.sh": "broken"})
	originalRelease, err := publishBytes(store, "demo", "1.0.0", original, rolePublisher)
	if err != nil {
		t.Fatalf("publish original: %v", err)
	}
	fixed := testTar(t, map[string]string{"install.sh": "fixed"})
	repairRelease, err := store.Publish(PublishRequest{
		Name:     "demo",
		Version:  "1.0.1",
		Artifact: bytes.NewReader(fixed),
		Publisher: Publisher{
			User: "admin-user",
			Role: roleAdmin,
		},
		Repair: &RepairInfo{OfVersion: "1.0.0", Reason: "fix install"},
	})
	if err != nil {
		t.Fatalf("publish repair: %v", err)
	}
	if repairRelease.Repair == nil || repairRelease.Repair.OfVersion != "1.0.0" {
		t.Fatalf("repair metadata missing: %+v", repairRelease.Repair)
	}
	after, err := store.Release("demo", "1.0.0")
	if err != nil {
		t.Fatalf("reload original: %v", err)
	}
	beforeJSON, _ := json.Marshal(originalRelease)
	afterJSON, _ := json.Marshal(after)
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatalf("original release changed after repair")
	}
}

func TestRepairRequiresAdminAndExistingBase(t *testing.T) {
	store := newTestStore(t)
	artifact := testTar(t, map[string]string{"README": "content"})
	_, err := store.Publish(PublishRequest{
		Name:      "demo",
		Version:   "2.0.0",
		Artifact:  bytes.NewReader(artifact),
		Publisher: Publisher{User: "publisher", Role: rolePublisher},
		Repair:    &RepairInfo{OfVersion: "1.0.0", Reason: "fix"},
	})
	if err != errRepairRequiresAdmin {
		t.Fatalf("publisher repair error = %v, want %v", err, errRepairRequiresAdmin)
	}
	_, err = store.Publish(PublishRequest{
		Name:      "demo",
		Version:   "2.0.0",
		Artifact:  bytes.NewReader(artifact),
		Publisher: Publisher{User: "admin", Role: roleAdmin},
		Repair:    &RepairInfo{OfVersion: "1.0.0", Reason: "fix"},
	})
	if err != errRepairBaseNotFound {
		t.Fatalf("missing base error = %v, want %v", err, errRepairBaseNotFound)
	}
}

func TestTamperedObjectFailsVerification(t *testing.T) {
	store := newTestStore(t)
	artifact := testTar(t, map[string]string{"README": "original"})
	release, err := publishBytes(store, "demo", "1.0.0", artifact, rolePublisher)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	digest := strings.TrimPrefix(release.ContentDigest, "sha256:")
	objectPath := filepath.Join(store.objectDir, digest+".tar")
	if err := os.WriteFile(objectPath, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper object: %v", err)
	}
	verification := store.Verify(release)
	if verification.Valid || verification.DigestValid {
		t.Fatalf("tampered archive passed verification: %+v", verification)
	}
}

func TestTamperedMetadataFailsSignatureVerification(t *testing.T) {
	store := newTestStore(t)
	artifact := testTar(t, map[string]string{"README": "original"})
	release, err := publishBytes(store, "demo", "1.0.0", artifact, rolePublisher)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	release.Publisher.User = "forged-user"
	release.Publisher.Role = roleAdmin
	data, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered metadata: %v", err)
	}
	if err := os.WriteFile(store.releasePath("demo", "1.0.0"), data, 0o644); err != nil {
		t.Fatalf("tamper metadata: %v", err)
	}
	loaded, err := store.Release("demo", "1.0.0")
	if err != nil {
		t.Fatalf("load tampered metadata: %v", err)
	}
	verification := store.Verify(loaded)
	if verification.Valid || verification.SignatureValid {
		t.Fatalf("tampered metadata passed verification: %+v", verification)
	}
}

func TestInvalidTarIsRejected(t *testing.T) {
	store := newTestStore(t)
	_, err := publishBytes(store, "demo", "1.0.0", []byte("not a tar"), rolePublisher)
	if !errors.Is(err, errInvalidArchive) {
		t.Fatalf("error = %v, want %v", err, errInvalidArchive)
	}
}
