package main

import (
	"os"
	"path/filepath"
	"testing"
)

// repoRoot walks up from the test working directory until it finds go.mod and
// the fixtures directory, so tests are robust to the package cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "fixtures")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate repository root with fixtures/")
	return ""
}

func fixtureConfig(t *testing.T, rel ...string) string {
	t.Helper()
	parts := append([]string{repoRoot(t), "fixtures"}, rel...)
	return filepath.Join(parts...)
}
