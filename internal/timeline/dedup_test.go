package timeline

import "testing"

func TestDedupKeyDeterministic(t *testing.T) {
	base := IngestInput{
		FileID:     "f1",
		Action:     ActionDownload,
		ActorID:    "u1",
		VersionID:  "v1",
		OccurredAt: parseTestTime(t, "2026-11-26T08:00:00Z"),
		Details: map[string]string{
			"ip":     "10.0.0.1",
			"client": "web",
		},
	}
	// Reordering detail entries must not change the key.
	reordered := base
	reordered.Details = map[string]string{
		"client": "web",
		"ip":     "10.0.0.1",
	}
	if got, want := DedupKey(base), DedupKey(reordered); got != want {
		t.Fatalf("detail ordering changed dedup key: %s != %s", got, want)
	}
	if len(DedupKey(base)) < 16 {
		t.Fatalf("dedup key looks too short: %q", DedupKey(base))
	}

	// A different actor is a different logical event.
	other := base
	other.ActorID = "u2"
	if DedupKey(base) == DedupKey(other) {
		t.Fatal("distinct events produced the same dedup key")
	}

	// Idempotency-token mode collapses to token + file + action only.
	tok1 := IngestInput{FileID: "f1", Action: ActionPreview, ActorID: "u1", ClientEventID: "tok-7"}
	tok2 := IngestInput{FileID: "f1", Action: ActionPreview, ActorID: "u9", ClientEventID: "tok-7"}
	if DedupKey(tok1) != DedupKey(tok2) {
		t.Fatal("same client token should produce the same dedup key")
	}
	tok3 := tok1
	tok3.ClientEventID = "tok-8"
	if DedupKey(tok1) == DedupKey(tok3) {
		t.Fatal("different client tokens should produce different keys")
	}

	// The same upstream token on different files must not collide.
	tokOtherFile := tok1
	tokOtherFile.FileID = "f2"
	if DedupKey(tok1) == DedupKey(tokOtherFile) {
		t.Fatal("same token on different files should produce different keys")
	}
}
