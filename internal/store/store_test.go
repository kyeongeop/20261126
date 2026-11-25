package store

import (
	"os"
	"path/filepath"
	"testing"

	"fileshare/internal/keyring"
)

func setupStore(t *testing.T) (*Store, *keyring.Keyring, string) {
	t.Helper()
	dataDir := t.TempDir()
	kr, err := keyring.Open(filepath.Join(dataDir, "keyring"), "alice")
	if err != nil {
		t.Fatalf("keyring open: %v", err)
	}
	return New(dataDir, kr), kr, dataDir
}

func TestVersionedEncryptionAndRotationReadback(t *testing.T) {
	st, kr, dataDir := setupStore(t)

	v1, err := st.AddVersion("report", "report.txt", "alice", "initial", []byte("draft content"))
	if err != nil {
		t.Fatalf("add v1: %v", err)
	}
	v2, err := st.AddVersion("report", "report.txt", "bob", "edit", []byte("reviewed content"))
	if err != nil {
		t.Fatalf("add v2: %v", err)
	}
	if v1.KeyVersion != 1 || v2.KeyVersion != 1 {
		t.Fatalf("expected first versions under KEK v1, got %d/%d", v1.KeyVersion, v2.KeyVersion)
	}

	// Snapshot historical ciphertext blobs before rotation. Rotation and any
	// subsequent reads must never rewrite them.
	blobV1 := filepath.Join(dataDir, v1.BlobPath)
	blobV2 := filepath.Join(dataDir, v2.BlobPath)
	before1, err := os.ReadFile(blobV1)
	if err != nil {
		t.Fatal(err)
	}
	before2, err := os.ReadFile(blobV2)
	if err != nil {
		t.Fatal(err)
	}

	newKey, err := kr.Rotate("carol")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newKey.Version != 2 || kr.ActiveVersion() != 2 {
		t.Fatalf("expected active KEK v2 after rotation, got meta=%d active=%d",
			newKey.Version, kr.ActiveVersion())
	}

	v3, err := st.AddVersion("report", "report.txt", "carol", "post-rotation",
		[]byte("final content"))
	if err != nil {
		t.Fatalf("add v3: %v", err)
	}
	if v3.KeyVersion != 2 {
		t.Fatalf("new version must wrap DEK with new KEK, got v%d", v3.KeyVersion)
	}

	after1, err := os.ReadFile(blobV1)
	if err != nil {
		t.Fatal(err)
	}
	after2, err := os.ReadFile(blobV2)
	if err != nil {
		t.Fatal(err)
	}
	if string(after1) != string(before1) {
		t.Fatal("historical ciphertext v1 was rewritten after key rotation")
	}
	if string(after2) != string(before2) {
		t.Fatal("historical ciphertext v2 was rewritten after key rotation")
	}

	cases := []struct {
		number  int
		want    string
		creator string
		keyVer  int
	}{
		{1, "draft content", "alice", 1},
		{2, "reviewed content", "bob", 1},
		{3, "final content", "carol", 2},
	}
	for _, tc := range cases {
		got, entry, err := st.ReadVersion("report", tc.number)
		if err != nil {
			t.Fatalf("read v%d: %v", tc.number, err)
		}
		if string(got) != tc.want {
			t.Fatalf("v%d plaintext = %q, want %q", tc.number, got, tc.want)
		}
		if entry.CreatedBy != tc.creator {
			t.Fatalf("v%d creator = %q, want %q", tc.number, entry.CreatedBy, tc.creator)
		}
		if entry.KeyVersion != tc.keyVer {
			t.Fatalf("v%d key version = %d, want %d", tc.number, entry.KeyVersion, tc.keyVer)
		}
		if entry.PlainSHA256 == "" || entry.CipherSHA256 == "" {
			t.Fatalf("v%d missing checksums", tc.number)
		}
	}

	// Reading must remain non-mutating.
	readAgain1, err := os.ReadFile(blobV1)
	if err != nil {
		t.Fatal(err)
	}
	if string(readAgain1) != string(before1) {
		t.Fatal("ciphertext v1 changed during readback")
	}

	// Keyring retains every KEK version with its creator.
	keys := kr.List()
	if len(keys) != 2 || keys[0].CreatedBy != "alice" || keys[1].CreatedBy != "carol" {
		t.Fatalf("unexpected keyring metadata: %+v", keys)
	}

	pub, err := st.PublicManifest("report")
	if err != nil {
		t.Fatal(err)
	}
	if pub.Latest != 3 || len(pub.Versions) != 3 {
		t.Fatalf("manifest mismatch: %+v", pub)
	}
}

func TestReadVersionDetectsTampering(t *testing.T) {
	st, _, dataDir := setupStore(t)
	entry, err := st.AddVersion("doc", "doc.txt", "alice", "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	blobPath := filepath.Join(dataDir, entry.BlobPath)
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xFF
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ReadVersion("doc", 1); err == nil {
		t.Fatal("expected checksum/authentication failure on tampered blob")
	}
}

func TestReadUnknownVersion(t *testing.T) {
	st, _, _ := setupStore(t)
	if _, err := st.AddVersion("f", "f.txt", "alice", "", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ReadVersion("f", 99); err == nil {
		t.Fatal("expected ErrNotFound for missing version")
	}
}
