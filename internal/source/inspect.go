package source

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DuplicateEntry identifies a package path that appears more than once in a
// transfer source. Bundles are produced by external systems, so duplicates
// must be detected explicitly instead of silently overwriting files.
type DuplicateEntry struct {
	Path  string
	Count int
}

// TarDuplicates scans an uncompressed tar archive and lists regular-file
// paths occurring more than once.
func TarDuplicates(archivePath string) ([]DuplicateEntry, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	counts := map[string]int{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			counts[hdr.Name]++
		}
	}
	return collectDuplicates(counts), nil
}

// DirDuplicates scans a directory for path collisions. It catches two cases:
// two distinct on-disk entries that normalize to the same manifest path, and
// case-insensitive file systems where "A.deb" and "a.deb" map to one file.
func DirDuplicates(root string) ([]DuplicateEntry, error) {
	normalized := map[string]int{}
	caseFolded := map[string]string{}
	err := filepath.WalkDir(root, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, full)
		if relErr != nil {
			return relErr
		}
		rel = strings.ReplaceAll(rel, "\\", "/")
		normalized[rel]++
		caseFolded[strings.ToLower(rel)] = rel
		return nil
	})
	if err != nil {
		return nil, err
	}
	dupes := collectDuplicates(normalized)
	seen := map[string]bool{}
	for _, d := range dupes {
		seen[d.Path] = true
	}
	foldedCounts := map[string]int{}
	for p := range normalized {
		foldedCounts[strings.ToLower(p)]++
	}
	for folded, count := range foldedCounts {
		if count > 1 && !seen[folded] {
			dupes = append(dupes, DuplicateEntry{Path: folded, Count: count})
		}
	}
	return dupes, nil
}

func collectDuplicates(counts map[string]int) []DuplicateEntry {
	var out []DuplicateEntry
	for path, count := range counts {
		if count > 1 {
			out = append(out, DuplicateEntry{Path: path, Count: count})
		}
	}
	return out
}
