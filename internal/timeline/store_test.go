package timeline

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func parseTestTime(t *testing.T, raw string) time.Time {
	t.Helper()
	got, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return got.UTC()
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestIngestDedupAndTombstone(t *testing.T) {
	store := newTestStore(t)
	input := IngestInput{
		FileID:     "f1",
		Action:     ActionPreview,
		ActorID:    "u1",
		OccurredAt: parseTestTime(t, "2026-11-26T08:00:00Z"),
		Details:    map[string]string{"ip": "10.0.0.1"},
	}
	first, err := store.Ingest(input)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if first.Duplicate || first.Suppressed {
		t.Fatal("first ingest should be a fresh event")
	}

	// Re-reporting the same logical event is idempotent.
	again, err := store.Ingest(input)
	if err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	if !again.Duplicate || again.Event.DedupKey != first.Event.DedupKey {
		t.Fatalf("duplicate not detected: %+v", again)
	}

	info, _ := store.GetFile("f1")
	if info.EventCount != 1 {
		t.Fatalf("event count = %d, want 1", info.EventCount)
	}

	// Deleting tombstones the key; a later duplicate report stays suppressed.
	if err := store.Delete(first.Event.DedupKey); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(first.Event.DedupKey); !errors.Is(err, ErrDeleted) {
		t.Fatalf("get after delete = %v, want ErrDeleted", err)
	}
	reReport, err := store.Ingest(input)
	if err != nil {
		t.Fatalf("re-report after delete: %v", err)
	}
	if !reReport.Suppressed {
		t.Fatal("re-report of a tombstoned event should be suppressed")
	}
	if !store.IsDeleted(first.Event.DedupKey) {
		t.Fatal("dedup key should remain reserved after deletion")
	}

	// Deleting an unknown key and double-deleting surface explicit errors.
	if err := store.Delete("evt_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing = %v, want ErrNotFound", err)
	}
	if err := store.Delete(first.Event.DedupKey); !errors.Is(err, ErrDeleted) {
		t.Fatalf("double delete = %v, want ErrDeleted", err)
	}
}

func TestVersionDerivationAndVersions(t *testing.T) {
	store := newTestStore(t)

	create := IngestInput{FileID: "f1", Action: ActionCreate, ActorID: "u1",
		OccurredAt: parseTestTime(t, "2026-11-26T08:00:00Z")}
	created, err := store.Ingest(create)
	if err != nil {
		t.Fatalf("ingest create: %v", err)
	}
	if created.Event.VersionID != "v1" {
		t.Fatalf("create version = %q, want v1", created.Event.VersionID)
	}

	preview := IngestInput{FileID: "f1", Action: ActionPreview, ActorID: "u2",
		OccurredAt: parseTestTime(t, "2026-11-26T09:00:00Z")}
	prev, _ := store.Ingest(preview)
	if prev.Event.VersionID != "v1" {
		t.Fatalf("preview version = %q, want inherited v1", prev.Event.VersionID)
	}

	upload := IngestInput{FileID: "f1", Action: ActionUpdate, ActorID: "u1",
		VersionID: "v2", OccurredAt: parseTestTime(t, "2026-11-26T10:00:00Z")}
	if _, err := store.Ingest(upload); err != nil {
		t.Fatalf("ingest update: %v", err)
	}
	download := IngestInput{FileID: "f1", Action: ActionDownload, ActorID: "u2",
		OccurredAt: parseTestTime(t, "2026-11-26T11:00:00Z")}
	dl, _ := store.Ingest(download)
	if dl.Event.VersionID != "v2" {
		t.Fatalf("download version = %q, want latest v2", dl.Event.VersionID)
	}

	info, _ := store.GetFile("f1")
	if got, want := fmt.Sprint(info.Versions), "[v1 v2]"; got != want {
		t.Fatalf("versions = %s, want %s", got, want)
	}
}

func TestListFiltersAndOrder(t *testing.T) {
	store := newTestStore(t)
	events := []IngestInput{
		{FileID: "f1", Action: ActionCreate, ActorID: "u1", VersionID: "v1",
			OccurredAt: parseTestTime(t, "2026-11-26T08:00:00Z")},
		{FileID: "f1", Action: ActionGrant, ActorID: "admin", VersionID: "v1",
			OccurredAt: parseTestTime(t, "2026-11-26T09:00:00Z"),
			Details:    map[string]string{"grantee": "u2", "role": "viewer"}},
		{FileID: "f1", Action: ActionPreview, ActorID: "u2", VersionID: "v1",
			OccurredAt: parseTestTime(t, "2026-11-26T10:00:00Z")},
		{FileID: "f1", Action: ActionDownload, ActorID: "u2", VersionID: "v2",
			OccurredAt: parseTestTime(t, "2026-11-26T11:00:00Z")},
		{FileID: "f1", Action: ActionMove, ActorID: "admin", VersionID: "v2",
			OccurredAt: parseTestTime(t, "2026-11-26T12:00:00Z"),
			Details:    map[string]string{"from_path": "/a", "to_path": "/b"}},
		{FileID: "f1", Action: ActionRevoke, ActorID: "admin", VersionID: "v2",
			OccurredAt: parseTestTime(t, "2026-11-26T13:00:00Z"),
			Details:    map[string]string{"revokee": "u2"}},
	}
	for _, input := range events {
		if _, err := store.Ingest(input); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	page, err := store.List(Filter{FileID: "f1"}, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Filtered != 6 || page.Total != 6 {
		t.Fatalf("counts = %+v, want 6/6", page)
	}
	if page.Events[0].Action != ActionCreate || page.Events[5].Action != ActionRevoke {
		t.Fatal("timeline not ordered by occurrence time")
	}

	// User filter matches the actor and referenced users (grantee/revokee).
	page, _ = store.List(Filter{FileID: "f1", User: "u2"}, 0)
	if page.Filtered != 4 {
		t.Fatalf("u2 events = %d, want 4 (preview, download, grant, revoke)", page.Filtered)
	}

	page, _ = store.List(Filter{FileID: "f1", Action: ActionDownload}, 0)
	if page.Filtered != 1 || page.Events[0].Action != ActionDownload {
		t.Fatalf("action filter failed: %+v", page)
	}

	page, _ = store.List(Filter{FileID: "f1", VersionID: "v2"}, 0)
	if page.Filtered != 3 {
		t.Fatalf("v2 events = %d, want 3", page.Filtered)
	}

	page, _ = store.List(Filter{
		FileID: "f1",
		From:   parseTestTime(t, "2026-11-26T09:30:00Z"),
		To:     parseTestTime(t, "2026-11-26T11:30:00Z"),
	}, 0)
	if page.Filtered != 2 {
		t.Fatalf("time window events = %d, want 2", page.Filtered)
	}

	page, _ = store.List(Filter{FileID: "f1"}, 2)
	if !page.Truncated || len(page.Events) != 2 || page.Limit != 2 {
		t.Fatalf("limit handling failed: %+v", page)
	}

	info, _ := store.GetFile("f1")
	if info.CurrentPath != "/b" {
		t.Fatalf("current path = %q, want /b", info.CurrentPath)
	}
}

func TestReplayRestoresEventsAndTombstones(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	input := IngestInput{FileID: "f1", Action: ActionCreate, ActorID: "u1",
		OccurredAt: parseTestTime(t, "2026-11-26T08:00:00Z")}
	created, _ := store.Ingest(input)
	second, _ := store.Ingest(IngestInput{
		FileID: "f1", Action: ActionPreview, ActorID: "u1",
		OccurredAt: parseTestTime(t, "2026-11-26T09:00:00Z"),
	})
	if err := store.Delete(second.Event.DedupKey); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	info, err := reopened.GetFile("f1")
	if err != nil {
		t.Fatalf("get file: %v", err)
	}
	if info.EventCount != 1 || len(info.DeletedKeys) != 1 {
		t.Fatalf("after replay counts = %+v, want 1 live / 1 deleted", info)
	}
	if _, err := reopened.Get(created.Event.DedupKey); err != nil {
		t.Fatalf("surviving event missing: %v", err)
	}
	if _, err := reopened.Get(second.Event.DedupKey); !errors.Is(err, ErrDeleted) {
		t.Fatalf("tombstone not restored: %v", err)
	}

	// The sequence continues past the replayed max value.
	next, err := reopened.Ingest(IngestInput{
		FileID: "f1", Action: ActionDownload, ActorID: "u1",
		OccurredAt: parseTestTime(t, "2026-11-26T10:00:00Z"),
	})
	if err != nil {
		t.Fatalf("ingest after replay: %v", err)
	}
	if next.Event.Seq <= second.Event.Seq {
		t.Fatalf("seq not continued: new=%d old=%d", next.Event.Seq, second.Event.Seq)
	}

	// A duplicate report of the replayed tombstoned event stays suppressed.
	again, err := reopened.Ingest(IngestInput{
		FileID: "f1", Action: ActionPreview, ActorID: "u1",
		OccurredAt: parseTestTime(t, "2026-11-26T09:00:00Z"),
	})
	if err != nil || !again.Suppressed {
		t.Fatalf("replayed tombstone suppression failed: %+v err=%v", again, err)
	}
}

func TestInvalidInputRejected(t *testing.T) {
	store := newTestStore(t)
	cases := []IngestInput{
		{Action: ActionCreate, ActorID: "u1"},
		{FileID: "f1", ActorID: "u1"},
		{FileID: "f1", Action: "explode", ActorID: "u1"},
		{FileID: "f1", Action: ActionCreate},
	}
	for index, input := range cases {
		if _, err := store.Ingest(input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d: err = %v, want ErrInvalid", index, err)
		}
	}
	if _, err := store.List(Filter{}, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("list without file id: err = %v, want ErrInvalid", err)
	}
	if _, err := store.GetFile("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file: want ErrNotFound")
	}
}
