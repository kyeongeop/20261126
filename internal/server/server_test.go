package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"teamsync/internal/model"
	"teamsync/internal/store"
)

type fixture struct {
	t      *testing.T
	store  *store.Store
	server *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, store: st, server: httptest.NewServer(New(st))}
}

func (f *fixture) close() { f.server.Close() }

func (f *fixture) do(method, path, actor string, body any) (int, map[string]any) {
	f.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, f.server.URL+path, reader)
	if err != nil {
		f.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if actor != "" {
		req.Header.Set("X-Actor-Id", actor)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return res.StatusCode, out
}

func (f *fixture) mustDo(method, path, actor string, body any) map[string]any {
	f.t.Helper()
	status, out := f.do(method, path, actor, body)
	if status < 200 || status >= 300 {
		f.t.Fatalf("%s %s -> %d %v", method, path, status, out)
	}
	return out
}

func (f *fixture) createUser(name string) map[string]any {
	return f.mustDo("POST", "/api/users", "", map[string]string{"name": name})
}

func (f *fixture) createNode(name, kind, parent string) map[string]any {
	return f.mustDo("POST", "/api/nodes", "", map[string]string{"name": name, "kind": kind, "parentId": parent})
}

func idOf(m map[string]any) string { return m["id"].(string) }

func TestPermissionEndToEndAndSameNameUsers(t *testing.T) {
	f := newFixture(t)
	defer f.close()

	bob1 := f.createUser("Bob")
	bob2 := f.createUser("Bob")
	if idOf(bob1) == idOf(bob2) {
		t.Fatal("same-name users need distinct IDs")
	}

	rootID := f.store.RootID()
	eng := f.createNode("Engineering", model.KindFolder, rootID)
	design := f.createNode("Design", model.KindFolder, idOf(eng))
	doc := f.createNode("spec.md", model.KindFile, idOf(design))

	// Root-level read for Bob1, Design-level admin for Bob2.
	f.mustDo("PUT", "/api/nodes/"+rootID+"/permissions/"+idOf(bob1), "", map[string]string{"level": "read"})
	f.mustDo("PUT", "/api/nodes/"+idOf(design)+"/permissions/"+idOf(bob2), "", map[string]string{"level": "admin"})

	status, _ := f.do("GET", "/api/nodes/"+idOf(doc)+"/permissions", idOf(bob1), nil)
	if status != http.StatusOK {
		t.Fatalf("Bob1 read access = %d, want 200", status)
	}
	status, _ = f.do("GET", "/api/nodes/"+idOf(doc)+"/permissions", idOf(bob2), nil)
	if status != http.StatusOK {
		t.Fatalf("Bob2 admin implies read, got %d", status)
	}

	// Bob1 only has read and must not be able to add overrides.
	status, body := f.do("PUT", "/api/nodes/"+idOf(design)+"/permissions/"+idOf(bob1), idOf(bob1),
		map[string]string{"level": "admin"})
	if status != http.StatusForbidden {
		t.Fatalf("read-only user override status = %d body=%v", status, body)
	}

	// Bob2 is admin on Design and can set a none override for Bob1.
	f.mustDo("PUT", "/api/nodes/"+idOf(design)+"/permissions/"+idOf(bob1), idOf(bob2),
		map[string]string{"level": "none"})
	status, _ = f.do("GET", "/api/nodes/"+idOf(doc)+"/permissions", idOf(bob1), nil)
	if status != http.StatusForbidden {
		t.Fatalf("none override must deny Bob1 on the file, got %d", status)
	}

	// The editor payload must show where each effective row comes from.
	view := f.mustDo("GET", "/api/nodes/"+idOf(doc)+"/permissions", "", nil)
	entries := view["entries"].([]any)
	found := false
	for _, raw := range entries {
		entry := raw.(map[string]any)
		if entry["userId"] == idOf(bob1) {
			found = true
			if entry["level"] != "none" || entry["sourceNode"] != idOf(design) || entry["inherited"] != true {
				t.Fatalf("Bob1 effective row missing source annotation: %v", entry)
			}
		}
	}
	if !found {
		t.Fatal("editor payload missing Bob1 row")
	}

	// Invalid levels are rejected.
	status, _ = f.do("PUT", "/api/nodes/"+rootID+"/permissions/"+idOf(bob1), "", map[string]string{"level": "owner"})
	if status != http.StatusBadRequest {
		t.Fatalf("invalid level status = %d, want 400", status)
	}
}

func TestMoveEndpointRecomputesAndEnforces(t *testing.T) {
	f := newFixture(t)
	defer f.close()

	alice := f.createUser("Alice")
	rootID := f.store.RootID()
	eng := f.createNode("Engineering", model.KindFolder, rootID)
	sales := f.createNode("Sales", model.KindFolder, rootID)
	secret := f.createNode("Secret", model.KindFolder, idOf(eng))

	// Alice admin only inside Engineering; she has no rights on Sales.
	f.mustDo("PUT", "/api/nodes/"+idOf(eng)+"/permissions/"+idOf(alice), "", map[string]string{"level": "admin"})

	status, _ := f.do("POST", "/api/nodes/"+idOf(secret)+"/move", idOf(alice),
		map[string]string{"newParentId": idOf(sales)})
	if status != http.StatusForbidden {
		t.Fatalf("move without destination write = %d, want 403", status)
	}

	// Admin bootstrap performs the move; the engine then recomputes access.
	moved := f.mustDo("POST", "/api/nodes/"+idOf(secret)+"/move", "", map[string]string{"newParentId": idOf(sales)})
	node := moved["node"].(map[string]any)
	if node["path"] != "/Sales/Secret" {
		t.Fatalf("moved path = %v", node["path"])
	}
	status, _ = f.do("GET", "/api/nodes/"+idOf(secret)+"/permissions", idOf(alice), nil)
	if status != http.StatusForbidden {
		t.Fatalf("Alice must lose Engineering-scoped access after move, got %d", status)
	}

	// Moving into a descendant is a 422 validation failure.
	status, _ = f.do("POST", "/api/nodes/"+idOf(sales)+"/move", "", map[string]string{"newParentId": idOf(secret)})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("cycle move status = %d, want 422", status)
	}
}

func TestEditorPageServed(t *testing.T) {
	f := newFixture(t)
	defer f.close()

	res, err := http.Get(f.server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("editor status = %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !bytes.Contains(body, []byte("TeamSync")) {
		t.Fatal("editor HTML not served at /")
	}
}
