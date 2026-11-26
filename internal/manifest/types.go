package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// ManifestVersion is the on-disk format version understood by this build.
const ManifestVersion = 1

// Manifest lists every package that belongs to an offline mirror image.
// It is stored as JSON and is the single source of truth for package names,
// sizes, SHA-256 digests and the integrity hash chain.
type Manifest struct {
	Version   int     `json:"version"`
	ImageID   string  `json:"imageId"`
	CreatedAt string  `json:"createdAt"`
	Packages  []Entry `json:"packages"`
	RootHash  string  `json:"rootHash"`
	Note      string  `json:"note,omitempty"`
}

// Entry describes one package inside the image.
type Entry struct {
	// Path is the package location relative to the image root. It always
	// uses forward slashes and never escapes the image root.
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// EntryHash binds an entry to its predecessor in the integrity chain:
//
//	entryHash  = SHA256(prevHash || "\n" || path || "\n" || size || "\n" || sha256 || "\n")
//
// The chain starts from the empty string. A single changed, removed,
// inserted or reordered entry therefore changes the final RootHash.
func EntryHash(prevHash, path string, size int64, digest string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	fmt.Fprintf(h, "\n%s\n%d\n%s\n", path, size, digest)
	return hex.EncodeToString(h.Sum(nil))
}

// RootHash computes the chained root digest over all entries in order.
func RootHash(entries []Entry) string {
	prev := ""
	for _, e := range entries {
		prev = EntryHash(prev, e.Path, e.Size, e.SHA256)
	}
	return prev
}

// Marshal renders the manifest to deterministic JSON (sorted struct fields,
// no map keys are used so encoding/json output is stable).
func (m *Manifest) Marshal() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// Parse decodes and validates a manifest. It rejects malformed paths, bad
// digests, and duplicated package paths instead of silently trusting them.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks structure, path safety, digest formatting and the hash chain.
func (m *Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("unsupported manifest version %d (want %d)", m.Version, ManifestVersion)
	}
	if strings.TrimSpace(m.ImageID) == "" {
		return fmt.Errorf("manifest imageId must not be empty")
	}
	seen := make(map[string]struct{}, len(m.Packages))
	for i, e := range m.Packages {
		if err := ValidatePath(e.Path); err != nil {
			return fmt.Errorf("package %d: %w", i, err)
		}
		if _, ok := seen[e.Path]; ok {
			return fmt.Errorf("package %d: duplicate path in manifest: %q", i, e.Path)
		}
		seen[e.Path] = struct{}{}
		if e.Size < 0 {
			return fmt.Errorf("package %q: negative size", e.Path)
		}
		if !validDigest(e.SHA256) {
			return fmt.Errorf("package %q: sha256 must be 64 lowercase hex characters", e.Path)
		}
	}
	computed := RootHash(m.Packages)
	if m.RootHash == "" {
		return fmt.Errorf("manifest rootHash must not be empty")
	}
	if computed != m.RootHash {
		return fmt.Errorf("manifest rootHash mismatch: computed %s, recorded %s", computed, m.RootHash)
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
