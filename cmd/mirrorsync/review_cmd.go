package main

import (
	"fmt"
	"os"
	"path/filepath"

	"mirrorsync/internal/sync"
)

// cmdReview is meant to run on a second machine. It recomputes package
// digests from the summary and, when present, from the portable checksums
// file, and can additionally re-validate the full signature chain.
func cmdReview(args []string) error {
	parsed, err := parseFlags(args)
	if err != nil {
		return err
	}
	flags, err := require(parsed, "image", "summary")
	if err != nil {
		return err
	}
	summary, err := sync.ReadSummary(flags["summary"])
	if err != nil {
		return err
	}

	problems := 0
	checksums := flags["checksums"]
	if checksums == "" {
		defaultPath := filepath.Join(flags["image"], sync.ChecksumsFile)
		if _, statErr := os.Stat(defaultPath); statErr == nil {
			checksums = defaultPath
		}
	}
	if checksums != "" {
		mismatches, checked, mismatchErr := sync.VerifyChecksums(flags["image"], checksums)
		if mismatchErr != nil {
			return mismatchErr
		}
		fmt.Printf("checksums: verified %d entries from %s\n", checked, checksums)
		for _, mm := range mismatches {
			problems++
			fmt.Printf("  [MISMATCH] %s: %s (expected %s)\n", mm.Path, mm.Detail, mm.Expected)
		}
	}

	// Re-run the structured manifest-based verification whenever the original
	// manifest and signature material travel with the image.
	if flags["manifest"] != "" {
		m, manifestBytes, loadErr := loadManifest(flags["manifest"])
		if loadErr != nil {
			return loadErr
		}
		if m.RootHash != summary.ManifestRoot {
			problems++
			fmt.Printf("  [MISMATCH] manifest root %s differs from summary root %s\n",
				m.RootHash, summary.ManifestRoot)
		}
		if flags["signature"] != "" && flags["root-cert"] != "" {
			if sigErr := verifySignature(manifestBytes, flags); sigErr != nil {
				problems++
				fmt.Printf("  [SIGNATURE] %v\n", sigErr)
			} else {
				fmt.Println("signature chain: OK")
			}
		}
		report, verifyErr := sync.VerifyImage(flags["image"], m)
		if verifyErr != nil {
			return verifyErr
		}
		printReport(report)
		if report.Problems() {
			problems += len(report.Missing) + len(report.Replaced) +
				len(report.Duplicated) + len(report.Extra)
		}
	}

	if problems > 0 {
		return fmt.Errorf("review found %d problem(s)", problems)
	}
	fmt.Println("review: all packages match the recorded summary")
	return nil
}
