package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"mirrorsync/internal/manifest"
)

// hashLocal computes the SHA-256 and size of a file in the destination.
func hashLocal(full string) (string, int64, error) {
	f, err := os.Open(full)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// findExtra walks the destination and returns regular files that are not
// declared by the manifest (ignoring mirrorsync's own state file).
func (e *Engine) findExtra(m *manifest.Manifest) ([]PackageFinding, error) {
	declared := make(map[string]struct{}, len(m.Packages))
	for _, p := range m.Packages {
		declared[p.Path] = struct{}{}
	}
	var extras []PackageFinding
	err := filepath.WalkDir(e.DestDir, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(e.DestDir, full)
		if relErr != nil {
			return relErr
		}
		rel = manifest.RelativePath(rel)
		if isInternalFile(rel) {
			return nil
		}
		if _, ok := declared[rel]; ok {
			return nil
		}
		actual, size, hashErr := hashLocal(full)
		if hashErr != nil {
			return hashErr
		}
		extras = append(extras, PackageFinding{
			Path: rel, Status: StatusReplaced, Actual: actual, Size: size,
			Detail: "present on disk but not declared in manifest",
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return extras, nil
}

// isInternalFile reports files written by mirrorsync itself, which must not
// be treated as undeclared packages.
func isInternalFile(rel string) bool {
	switch rel {
	case checkpointName, SummaryFile, ChecksumsFile:
		return true
	}
	return strings.HasPrefix(rel, checkpointName+".")
}

// VerifyImage re-checks an already populated destination directory against a
// manifest without downloading anything. It is the building block of the
// cross-machine review command.
func VerifyImage(destDir string, m *manifest.Manifest) (*Report, error) {
	report := NewReport(m.ImageID)
	report.TotalListed = len(m.Packages)
	seen := map[string]int{}
	for _, entry := range m.Packages {
		seen[entry.Path]++
		full := filepath.Join(destDir, filepath.FromSlash(entry.Path))
		actual, size, err := hashLocal(full)
		switch {
		case err != nil && os.IsNotExist(err):
			report.Missing = append(report.Missing, PackageFinding{
				Path: entry.Path, Status: StatusMissing, Expected: entry.SHA256})
			continue
		case err != nil:
			return nil, fmt.Errorf("reading %s: %w", entry.Path, err)
		}
		if actual != entry.SHA256 || size != entry.Size {
			report.Replaced = append(report.Replaced, PackageFinding{
				Path: entry.Path, Status: StatusReplaced,
				Expected: entry.SHA256, Actual: actual, Size: size,
				Detail: fmt.Sprintf("expected size %d digest %s", entry.Size, entry.SHA256),
			})
			continue
		}
		report.Verified++
	}
	for path, count := range seen {
		if count > 1 {
			report.Duplicated = append(report.Duplicated, PackageFinding{
				Path: path, Status: StatusDuplicate,
				Detail: fmt.Sprintf("listed %d times in manifest", count),
			})
		}
	}
	eng := &Engine{DestDir: destDir}
	extras, err := eng.findExtra(m)
	if err != nil {
		return nil, err
	}
	report.Extra = extras
	return report, nil
}
