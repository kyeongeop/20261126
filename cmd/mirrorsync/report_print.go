package main

import (
	"fmt"

	"mirrorsync/internal/manifest"
	"mirrorsync/internal/sync"
)

func verifyAndPrint(imageDir string, m *manifest.Manifest) (*sync.Report, error) {
	report, err := sync.VerifyImage(imageDir, m)
	if err != nil {
		return nil, err
	}
	printReport(report)
	return report, nil
}

func printReport(r *sync.Report) {
	fmt.Printf("image %s: %d listed, %d verified, %d missing, %d replaced, %d duplicated, %d extra\n",
		r.ImageID, r.TotalListed, r.Verified, len(r.Missing), len(r.Replaced),
		len(r.Duplicated), len(r.Extra))
	if r.ResumedCount > 0 || r.RetriedCount > 0 {
		fmt.Printf("transfers resumed: %d, retried: %d\n", r.ResumedCount, r.RetriedCount)
	}
	printFindings("MISSING", r.Missing)
	printFindings("REPLACED", r.Replaced)
	printFindings("DUPLICATED", r.Duplicated)
	printFindings("EXTRA", r.Extra)
}

func printFindings(label string, findings []sync.PackageFinding) {
	for _, f := range findings {
		line := fmt.Sprintf("  [%s] %s", label, f.Path)
		if f.Actual != "" {
			line += fmt.Sprintf(" (actual %s)", f.Actual)
		}
		if f.Detail != "" {
			line += ": " + f.Detail
		}
		fmt.Println(line)
	}
}
