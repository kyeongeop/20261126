package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func ucdMakeTar(files map[string]string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))})
		_, _ = io.WriteString(tw, content)
	}
	_ = tw.Close()
	return buf.Bytes()
}

type ucdEnv struct {
	t   *testing.T
	s   *Store
	srv *httptest.Server
	now time.Time
}

func ucdNewEnv(t *testing.T, cooldown time.Duration) *ucdEnv {
	t.Helper()
	st, err := NewStore(t.TempDir(), cooldown)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	env := &ucdEnv{t: t, s: st, now: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
	st.SetClock(func() time.Time { return env.now })
	auth := &authConfig{users: map[string]credential{
		"alice": {passwordHash: sha256.Sum256([]byte("apass")), role: RoleAdmin},
		"bob":   {passwordHash: sha256.Sum256([]byte("bpass")), role: RoleAdmin},
		"mo":    {passwordHash: sha256.Sum256([]byte("mpass")), role: RoleMaintainer},
		"vw":    {passwordHash: sha256.Sum256([]byte("vpass")), role: RoleViewer},
	}}
	app := NewApp(st, auth)
	env.srv = httptest.NewServer(app)
	t.Cleanup(env.srv.Close)
	return env
}

func (e *ucdEnv) advance(d time.Duration) { e.now = e.now.Add(d) }

func (e *ucdEnv) do(method, path string, body any, user, pass string) (int, map[string]any) {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, reader)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func ucdTarWithDeps(depsJSON string) []byte {
	files := map[string]string{}
	if depsJSON != "" {
		files["package.json"] = `{"name":"x","version":"1.0.0","dependencies":` + depsJSON + `}`
	} else {
		files["README.md"] = "hello"
	}
	return ucdMakeTar(files)
}

func TestUCD60017CooldownSuite(t *testing.T) {
	env := ucdNewEnv(t, time.Hour)
	st := env.s

	if _, err := st.Publish(PublishInput{Name: "lib", Version: "1.0.0", Artifact: ucdTarWithDeps("")}); err != nil {
		t.Fatal(err)
	}
	st.RecordDownload(DownloadRecord{Package: "lib", Version: "1.0.0", User: "ci"})
	st.AddBuild(BuildRecord{Package: "lib", Version: "1.0.0", Pipeline: "pipe-1", Status: "running"})

	t.Run("create_requires_auth", func(t *testing.T) {
		if code, _ := env.do("POST", "/api/deletion-requests", map[string]any{"name": "lib"}, "", ""); code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", code)
		}
		if code, _ := env.do("POST", "/api/deletion-requests", map[string]any{"name": "lib"}, "vw", "vpass"); code != http.StatusForbidden {
			t.Fatalf("viewer want 403, got %d", code)
		}
	})

	var id string
	t.Run("create_pending_with_impact", func(t *testing.T) {
		code, d := env.do("POST", "/api/deletion-requests", map[string]any{"name": "lib", "reason": "gone"}, "alice", "apass")
		if code != http.StatusCreated {
			t.Fatalf("want 201, got %d %v", code, d)
		}
		id, _ = d["id"].(string)
		if d["status"] != StatusPending {
			t.Fatalf("status=%v", d["status"])
		}
		impact, _ := d["impact"].(map[string]any)
		if impact == nil || impact["download_count"].(float64) < 1 || impact["active_build_count"].(float64) < 1 {
			t.Fatalf("impact missing: %v", d["impact"])
		}
	})

	t.Run("early_confirm_blocked", func(t *testing.T) {
		code, d := env.do("POST", "/api/deletion-requests/"+id+"/confirm", nil, "bob", "bpass")
		if code != http.StatusConflict || d["code"] != "cooldown_not_elapsed" {
			t.Fatalf("want not-due 409, got %d %v", code, d["code"])
		}
	})

	t.Run("same_person_confirm_forbidden_after_due", func(t *testing.T) {
		env.advance(61 * time.Minute)
		code, d := env.do("POST", "/api/deletion-requests/"+id+"/confirm", nil, "alice", "apass")
		if code != http.StatusForbidden || d["code"] != "different_confirmer_required" {
			t.Fatalf("want same-confirmer 403, got %d %v", code, d)
		}
	})

	t.Run("other_admin_confirms_and_deletes", func(t *testing.T) {
		code, d := env.do("POST", "/api/deletion-requests/"+id+"/confirm", nil, "bob", "bpass")
		if code != http.StatusOK || d["status"] != StatusDeleted {
			t.Fatalf("want deleted 200, got %d %v", code, d)
		}
		if code, _ := env.do("GET", "/api/packages/lib/versions/1.0.0", nil, "", ""); code != http.StatusNotFound {
			t.Fatalf("deleted version want 404, got %d", code)
		}
	})
}

func TestUCD60017WithdrawAndReferenceBlock(t *testing.T) {
	env := ucdNewEnv(t, time.Minute)
	st := env.s
	if _, err := st.Publish(PublishInput{Name: "core", Version: "2.0.0", Artifact: ucdTarWithDeps("")}); err != nil {
		t.Fatal(err)
	}

	t.Run("withdraw_returns_package", func(t *testing.T) {
		code, d := env.do("POST", "/api/deletion-requests", map[string]any{"name": "core"}, "mo", "mpass")
		if code != http.StatusCreated {
			t.Fatalf("create: %d %v", code, d)
		}
		id, _ := d["id"].(string)
		code, d = env.do("POST", "/api/deletion-requests/"+id+"/withdraw", nil, "mo", "mpass")
		if code != http.StatusOK || d["status"] != StatusWithdrawn {
			t.Fatalf("withdraw: %d %v", code, d)
		}
		if code, _ := env.do("GET", "/api/packages/core/versions/2.0.0", nil, "", ""); code != http.StatusOK {
			t.Fatalf("package should remain available after withdraw, got %d", code)
		}
	})

	t.Run("referenced_package_cannot_complete", func(t *testing.T) {
		st.AddReference(Reference{FromPackage: "app", ToPackage: "core"})
		code, d := env.do("POST", "/api/deletion-requests", map[string]any{"name": "core"}, "alice", "apass")
		if code != http.StatusCreated {
			t.Fatalf("create: %d %v", code, d)
		}
		id, _ := d["id"].(string)
		env.advance(2 * time.Minute)

		code, d = env.do("POST", "/api/deletion-requests/"+id+"/complete", nil, "alice", "apass")
		if code != http.StatusConflict || d["code"] != "package_referenced" {
			t.Fatalf("complete want ref block, got %d %v", code, d)
		}
		dr, _ := st.GetDeletion(id)
		if dr.Status != StatusPending {
			t.Fatalf("must stay pending instead of cooldown_completed, got %s", dr.Status)
		}

		code, d = env.do("POST", "/api/deletion-requests/"+id+"/confirm", nil, "bob", "bpass")
		if code != http.StatusConflict || d["code"] != "package_referenced" {
			t.Fatalf("confirm want ref block, got %d %v", code, d)
		}

		// 解除引用后，另一管理员确认成功。
		st.mu.Lock()
		st.State.References = nil
		st.mu.Unlock()
		code, d = env.do("POST", "/api/deletion-requests/"+id+"/confirm", nil, "bob", "bpass")
		if code != http.StatusOK || d["status"] != StatusDeleted {
			t.Fatalf("confirm after unblock: %d %v", code, d)
		}
	})
}

func TestUCD60017TarDependencyParsed(t *testing.T) {
	info, err := inspectTar(ucdTarWithDeps(`{"core-lib":"^1.0.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, dep := range info.Dependencies {
		if dep.Package == "core-lib" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dependency not parsed: %+v", info.Dependencies)
	}
}

func TestUCD60017ActorHeaderFlowAndPendingDownload(t *testing.T) {
	env := ucdNewEnv(t, time.Hour)
	st := env.s
	if _, err := st.Publish(PublishInput{Name: "dlpkg", Version: "1.0.0", Artifact: ucdTarWithDeps("")}); err != nil {
		t.Fatal(err)
	}

	callHeaders := func(method, path string, body any, headers map[string]string) (int, map[string]any) {
		var reader io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			reader = bytes.NewReader(raw)
		}
		req, _ := http.NewRequest(method, env.srv.URL+path, reader)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		out := map[string]any{}
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}

	h1 := map[string]string{"X-Actor-Id": "alice", "X-Actor-Role": "admin"}
	h2 := map[string]string{"X-Actor-Id": "bob", "X-Actor-Role": "admin"}

	if code, _ := callHeaders("POST", "/api/deletion-requests", map[string]any{"name": "dlpkg"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("missing identity want 401 got %d", code)
	}
	code, d := callHeaders("POST", "/api/deletion-requests", map[string]any{"name": "dlpkg"}, h1)
	if code != http.StatusCreated || d["status"] != StatusPending {
		t.Fatalf("actor create: %d %v", code, d)
	}
	id, _ := d["id"].(string)

	// 冷静期内包仍可下载，并带预警头。
	resp, err := http.Get(env.srv.URL + "/api/packages/dlpkg/versions/1.0.0/download")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Deletion-Pending") != "true" {
		t.Fatalf("pending download should stay available with warning, code=%d hdr=%q", resp.StatusCode, resp.Header.Get("X-Deletion-Pending"))
	}

	env.advance(2 * time.Hour)
	if code, _ := callHeaders("POST", "/api/deletion-requests/"+id+"/confirm", nil, h1); code != http.StatusForbidden {
		t.Fatalf("same actor want 403 got %d", code)
	}
	if code, d := callHeaders("POST", "/api/deletion-requests/"+id+"/confirm", nil, h2); code != http.StatusOK || d["status"] != StatusDeleted {
		t.Fatalf("other actor confirm: %d %v", code, d)
	}
}
