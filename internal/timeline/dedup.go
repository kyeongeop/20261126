package timeline

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// dedupPrefix keeps timeline hashes namespaced and makes the scheme obvious
// when keys are inspected in logs or tests.
const dedupPrefix = "evt_"

// DedupKey computes the stable identity of an event.
//
// The key is deterministic: the same logical event reported twice (for
// example an at-least-once webhook retry, or a re-report after the event was
// tombstoned) produces the same key. A client-supplied idempotency token is
// folded in when present; otherwise the canonical event fields are hashed.
func DedupKey(in IngestInput) string {
	h := sha256.New()
	h.Write([]byte("fileshare.timeline.v1\n"))
	writeField := func(name, value string) {
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write([]byte(value))
		h.Write([]byte{'\n'})
	}

	token := strings.TrimSpace(in.ClientEventID)
	if token != "" {
		writeField("client_event_id", token)
		writeField("file_id", in.FileID)
		writeField("action", string(in.Action))
	} else {
		writeField("file_id", in.FileID)
		writeField("action", string(in.Action))
		writeField("actor_id", in.ActorID)
		writeField("occurred_at", in.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000000Z"))
		writeField("version_id", in.VersionID)
		keys := make([]string, 0, len(in.Details))
		for key := range in.Details {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			writeField("detail:"+key, in.Details[key])
		}
	}

	return dedupPrefix + hex.EncodeToString(h.Sum(nil))
}
