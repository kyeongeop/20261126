package sync

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mirrorsync/internal/manifest"
)

// SummaryFile is the JSON summary produced after a successful sync. It is
// fully self-describing so a second machine can recompute every digest and
// compare without any database or network access.
const SummaryFile = "sync-summary.json"

// ChecksumsFile is the portable, line-oriented digest list in the classic
// "<sha256>  <relative path>" format.
const ChecksumsFile = "SHA256SUMS.txt"

// Summary is the cross-machine review artifact.
type Summary struct {
	ImageID      string           `json:"imageId"`
	GeneratedAt  string           `json:"generatedAt"`
	ManifestRoot string           `json:"manifestRootHash"`
	Report       *Report          `json:"report"`
	Packages     []manifest.Entry `json:"packages"`
}

// WriteSummary emits both the JSON summary and the SHA256SUMS text file into
// destDir so the result can be audited on another machine.
func WriteSummary(destDir string, m *manifest.Manifest, report *Report) (*Summary, error) {
	summary := &Summary{
		ImageID:      m.ImageID,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		ManifestRoot: m.RootHash,
		Report:       report,
		Packages:     m.Packages,
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(destDir, SummaryFile), data, 0o644); err != nil {
		return nil, err
	}
	if err := writeChecksums(destDir, m); err != nil {
		return nil, err
	}
	return summary, nil
}

func writeChecksums(destDir string, m *manifest.Manifest) error {
	f, err := os.Create(filepath.Join(destDir, ChecksumsFile))
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, p := range m.Packages {
		fmt.Fprintf(w, "%s  %s\n", p.SHA256, p.Path)
	}
	return w.Flush()
}

// ReadSummary loads a previously generated summary.
func ReadSummary(path string) (*Summary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Summary
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("invalid summary JSON: %w", err)
	}
	return &s, nil
}

// ChecksumMismatch describes one line of SHA256SUMS that did not verify.
type ChecksumMismatch struct {
	Path     string
	Expected string
	Actual   string
	Detail   string
}

// VerifyChecksums recomputes every digest listed in a SHA256SUMS-style file
// against files under destDir. It returns the mismatches (missing files are
// reported as mismatches with an explanatory detail).
func VerifyChecksums(destDir, checksumsPath string) ([]ChecksumMismatch, int, error) {
	f, err := os.Open(checksumsPath)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var mismatches []ChecksumMismatch
	checked := 0
	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		fields := strings.SplitN(scanner.Text(), "  ", 2)
		if len(fields) != 2 {
			return nil, checked, fmt.Errorf("line %d: expected '<sha256>  <path>' format", line)
		}
		expected, rel := fields[0], fields[1]
		checked++
		full := filepath.Join(destDir, filepath.FromSlash(rel))
		actual, err := digestFile(full)
		if err != nil {
			mismatches = append(mismatches, ChecksumMismatch{
				Path: rel, Expected: expected, Detail: err.Error(),
			})
			continue
		}
		if actual != expected {
			mismatches = append(mismatches, ChecksumMismatch{
				Path: rel, Expected: expected, Actual: actual, Detail: "digest mismatch",
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, checked, err
	}
	return mismatches, checked, nil
}

func digestFile(full string) (string, error) {
	f, err := os.Open(full)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
