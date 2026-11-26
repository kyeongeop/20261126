package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// RewriteLockfile applies the report's replacement plan to a normalized or
// npm-shaped lockfile and returns pretty-printed JSON plus the number of
// entries changed. It only rewrites "resolved"/"integrity" fields; all other
// content round-trips through a generic representation.
func RewriteLockfile(data []byte, report *Report) ([]byte, int, error) {
	byName := map[string][]SourceReplacement{}
	for _, rp := range report.Replacements {
		byName[rp.Package] = append(byName[rp.Package], rp)
	}
	if len(byName) == 0 {
		return data, 0, nil
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, 0, fmt.Errorf("parse lockfile for rewrite: %w", err)
	}

	changed := 0

	if entries, ok := doc["entries"].([]any); ok {
		for _, item := range entries {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			if applyReplacement(m, "resolved", "integrity", currentString(m, "resolved"), byName[name]) {
				changed++
			}
		}
	}

	if pkgs, ok := doc["packages"].(map[string]any); ok {
		for key, item := range pkgs {
			name := nameFromNodeModulesKey(key)
			if name == "" {
				continue
			}
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if applyReplacement(m, "resolved", "integrity", currentString(m, "resolved"), byName[name]) {
				changed++
			}
		}
	}

	if deps, ok := doc["dependencies"].(map[string]any); ok {
		changed += rewriteNpmDeps(deps, byName)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), changed, nil
}

func rewriteNpmDeps(deps map[string]any, byName map[string][]SourceReplacement) int {
	changed := 0
	for name, item := range deps {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if applyReplacement(m, "resolved", "integrity", currentString(m, "resolved"), byName[name]) {
			changed++
		}
		if nested, ok := m["dependencies"].(map[string]any); ok {
			changed += rewriteNpmDeps(nested, byName)
		}
	}
	return changed
}

func currentString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// applyReplacement picks the replacement matching the current resolved URL
// when possible and rewrites urlKey/digestKey.
func applyReplacement(m map[string]any, urlKey, digestKey, currentURL string, reps []SourceReplacement) bool {
	if len(reps) == 0 {
		return false
	}
	var rp *SourceReplacement
	for i := range reps {
		if reps[i].ReplacedSource == currentURL {
			rp = &reps[i]
			break
		}
	}
	if rp == nil {
		rp = &reps[0]
	}
	changed := false
	if rp.Candidate.SourceURL != "" && currentString(m, urlKey) != rp.Candidate.SourceURL {
		m[urlKey] = rp.Candidate.SourceURL
		changed = true
	}
	if rp.Candidate.SHA256 != "" {
		normalized, ok := NormalizeSHA256(rp.Candidate.SHA256)
		if ok && currentString(m, digestKey) != normalized {
			m[digestKey] = normalized
			changed = true
		}
	}
	// The source is now pinned to the safe candidate, so any stale
	// fallback marker from the risky resolution no longer applies.
	for _, stale := range []string{"via_fallback", "selection_reason"} {
		if _, exists := m[stale]; exists {
			delete(m, stale)
			changed = true
		}
	}
	return changed
}
