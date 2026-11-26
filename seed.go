package main

import (
	"archive/tar"
	"bytes"
	"io"
	"time"
)

// SeedDemoDataIfEmpty 在仓库完全没有包时写入一套贴近真实场景的演示数据。
func (s *Store) SeedDemoDataIfEmpty() bool {
	s.mu.Lock()
	empty := len(s.State.Packages) == 0
	s.mu.Unlock()
	if !empty {
		return false
	}
	s.SeedDemoData()
	return true
}

// SeedDemoData 写入演示包、下载记录与流水线构建。
func (s *Store) SeedDemoData() {
	mkTar := func(files map[string]string) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for name, content := range files {
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))})
			_, _ = io.WriteString(tw, content)
		}
		_ = tw.Close()
		return buf.Bytes()
	}
	pkgJSON := func(name, version string, deps map[string]string) map[string]string {
		// 通过手工拼接避免在播种逻辑里引入额外类型。
		var b bytes.Buffer
		b.WriteString(`{"name":"` + name + `","version":"` + version + `"`)
		if len(deps) > 0 {
			b.WriteString(`,"dependencies":{`)
			first := true
			for k, v := range deps {
				if !first {
					b.WriteByte(',')
				}
				first = false
				b.WriteString(`"` + k + `":"` + v + `"`)
			}
			b.WriteString(`}`)
		}
		b.WriteString(`}`)
		return map[string]string{"package.json": b.String(), "README.md": name + " " + version + "\n"}
	}

	demos := []struct {
		name    string
		version string
		deps    map[string]string
	}{
		{"core-utils", "1.5.0", nil},
		{"core-utils", "1.4.0", nil},
		{"metrics-sdk", "2.1.0", map[string]string{"core-utils": "^1.4.0"}},
		{"web-framework", "3.0.0", map[string]string{"core-utils": "^1.5.0", "metrics-sdk": "^2.1.0"}},
		{"pipeline-runner", "0.9.0", map[string]string{"core-utils": "~1.4.0"}},
		{"orphan-tool", "1.0.0", nil},
	}
	for _, d := range demos {
		_, _ = s.Publish(PublishInput{
			Name:       d.name,
			Version:    d.version,
			Artifact:   mkTar(pkgJSON(d.name, d.version, d.deps)),
			UploadedBy: "publisher",
		})
	}

	now := time.Now()
	_ = s.save(func() error {
		s.State.Downloads = append(s.State.Downloads,
			DownloadRecord{ID: "dl-seed-1", Package: "core-utils", Name: "core-utils", Version: "1.5.0", User: "ci-bot", RemoteAddr: "10.0.0.21", At: now.Add(-2 * time.Hour)},
			DownloadRecord{ID: "dl-seed-2", Package: "core-utils", Name: "core-utils", Version: "1.4.0", User: "alice", RemoteAddr: "10.0.0.34", At: now.Add(-26 * time.Hour)},
			DownloadRecord{ID: "dl-seed-3", Package: "core-utils", Name: "core-utils", Version: "1.5.0", User: "bob", RemoteAddr: "10.0.0.41", At: now.Add(-30 * time.Minute)},
			DownloadRecord{ID: "dl-seed-4", Package: "orphan-tool", Name: "orphan-tool", Version: "1.0.0", User: "carol", RemoteAddr: "10.0.0.52", At: now.Add(-3 * time.Hour)},
		)
		s.State.Builds = append(s.State.Builds,
			BuildRecord{ID: "build-seed-1", Pipeline: "checkout-service #4821", Package: "core-utils", Name: "core-utils", Version: "1.5.0", Status: "running", Actor: "alice", Branch: "main", URL: "https://ci.example/builds/4821", StartedAt: now.Add(-6 * time.Minute), CreatedAt: now.Add(-6 * time.Minute)},
			BuildRecord{ID: "build-seed-2", Pipeline: "billing-worker #993", Package: "core-utils", Name: "core-utils", Version: "1.4.0", Status: "running", Actor: "bob", Branch: "release/2026.11", StartedAt: now.Add(-2 * time.Minute), CreatedAt: now.Add(-2 * time.Minute)},
			BuildRecord{ID: "build-seed-3", Pipeline: "web-app image #7712", Package: "web-framework", Name: "web-framework", Version: "3.0.0", Status: "succeeded", Actor: "carol", Branch: "main", StartedAt: now.Add(-5 * time.Hour), FinishedAt: timePtr(now.Add(-4 * time.Hour)), CreatedAt: now.Add(-5 * time.Hour)},
			BuildRecord{ID: "build-seed-4", Pipeline: "data-pipeline #310", Package: "pipeline-runner", Name: "pipeline-runner", Version: "0.9.0", Status: "failed", Actor: "dave", Branch: "feat/audit", StartedAt: now.Add(-28 * time.Hour), FinishedAt: timePtr(now.Add(-27 * time.Hour)), CreatedAt: now.Add(-28 * time.Hour)},
			BuildRecord{ID: "build-seed-5", Pipeline: "edge-gateway #2088", Package: "metrics-sdk", Name: "metrics-sdk", Version: "2.1.0", Status: "queued", Actor: "erin", Branch: "main", StartedAt: now, CreatedAt: now},
		)
		s.State.Counters["download"] = len(s.State.Downloads)
		s.State.Counters["build"] = len(s.State.Builds)
		return nil
	})
}

func timePtr(t time.Time) *time.Time { return &t }
