package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Build walks imageRoot, hashes every regular file it finds and assembles a
// validated manifest whose RootHash is filled in. Files are enumerated in
// sorted order so repeated builds are deterministic.
func Build(imageRoot, imageID string) (*Manifest, error) {
	var entries []Entry
	err := filepath.WalkDir(imageRoot, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("unsupported non-regular file: %s", full)
		}
		rel, relErr := filepath.Rel(imageRoot, full)
		if relErr != nil {
			return relErr
		}
		entryPath := RelativePath(rel)
		if err := ValidatePath(entryPath); err != nil {
			return err
		}
		entry, hashErr := hashFile(full, entryPath)
		if hashErr != nil {
			return hashErr
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	m := &Manifest{
		Version:   ManifestVersion,
		ImageID:   imageID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Packages:  entries,
	}
	m.RootHash = RootHash(m.Packages)
	return m, m.Validate()
}

func hashFile(full, entryPath string) (Entry, error) {
	f, err := os.Open(full)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return Entry{}, fmt.Errorf("hashing %s: %w", entryPath, err)
	}
	return Entry{Path: entryPath, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// HashFile hashes an arbitrary open reader and returns the lowercase hex
// SHA-256 digest together with the number of bytes read.
func HashFile(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
