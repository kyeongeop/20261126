package main

import "sort"

// referrersLocked 返回当前仍活跃、且依赖目标包名的包版本/手工引用。调用方持锁。
func (s *Store) referrersLocked(target string) []Referrer {
	out := []Referrer{}
	seen := map[string]bool{}

	add := func(r Referrer) {
		if r.Package == "" || r.Package == target {
			return
		}
		key := r.Package + "\x00" + r.Version + "\x00" + r.Source
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, r)
	}

	for pkgName, pkg := range s.State.Packages {
		if pkgName == target {
			continue
		}
		versions := make([]string, 0, len(pkg.Versions))
		for v := range pkg.Versions {
			versions = append(versions, v)
		}
		sort.Strings(versions)
		for _, ver := range versions {
			v := pkg.Versions[ver]
			if v == nil || v.Deleted {
				continue
			}
			for _, dep := range v.Dependencies {
				if dep.Package == target {
					add(Referrer{
						Package:    pkgName,
						Name:       pkgName,
						Version:    ver,
						Constraint: dep.Constraint,
						Source:     dep.Source,
					})
				}
			}
		}
	}

	for _, ref := range s.State.References {
		if ref.ToPackage != target {
			continue
		}
		if ref.FromVersion != "" {
			if pkg, ok := s.State.Packages[ref.FromPackage]; ok {
				if v, ok := pkg.Versions[ref.FromVersion]; ok && v != nil && v.Deleted {
					continue
				}
			}
		}
		add(Referrer{
			Package:    ref.FromPackage,
			Name:       ref.FromPackage,
			Version:    ref.FromVersion,
			Constraint: ref.Constraint,
			Source:     firstNonEmpty(ref.Source, "reference"),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// impactLocked 汇总目标（包名 + 可选版本）受影响的下载、构建与引用。调用方持锁。
func (s *Store) impactLocked(name, version string) Impact {
	impact := Impact{
		Downloads:    []DownloadRecord{},
		Builds:       []BuildRecord{},
		ReferencedBy: s.referrersLocked(name),
	}
	impact.ReferrerCount = len(impact.ReferencedBy)

	for i := len(s.State.Downloads) - 1; i >= 0; i-- {
		d := s.State.Downloads[i]
		if d.Package != name && d.Name != name {
			continue
		}
		if version != "" && d.Version != "" && d.Version != version {
			continue
		}
		impact.Downloads = append(impact.Downloads, d)
	}
	impact.DownloadCount = len(impact.Downloads)

	for i := len(s.State.Builds) - 1; i >= 0; i-- {
		b := s.State.Builds[i]
		if b.Package != name && b.Name != name {
			continue
		}
		if version != "" && b.Version != "" && b.Version != version {
			continue
		}
		impact.Builds = append(impact.Builds, b)
		impact.BuildCount++
		if isActiveBuild(b.Status) {
			impact.ActiveBuildCount++
			impact.InProgressBuildCount++
		}
	}
	return impact
}

func isActiveBuild(status string) bool {
	switch status {
	case "running", "pending", "queued", "in_progress", "building":
		return true
	}
	return false
}

// Impact 返回某个目标的影响分析快照。
func (s *Store) Impact(name, version string) Impact {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.impactLocked(name, version)
}

// ReferencedBy 返回引用目标包的活跃包列表。
func (s *Store) ReferencedBy(name string) []Referrer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.referrersLocked(name)
}

// AllReferences 返回手工登记的引用关系（新记录在前）。
func (s *Store) AllReferences() []Reference {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Reference, 0, len(s.State.References))
	for i := len(s.State.References) - 1; i >= 0; i-- {
		out = append(out, s.State.References[i])
	}
	return out
}
