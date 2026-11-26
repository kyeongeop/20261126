package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PublishInput 是发布一个包版本所需的全部输入。
type PublishInput struct {
	Name       string
	Version    string
	Filename   string
	Artifact   []byte
	UploadedBy string
	// Dependencies 允许调用方在清单之外显式补充依赖。
	Dependencies []Dependency
}

// Publish 校验 tar、计算 sha256、写入内容寻址对象并登记不可变版本。
func (s *Store) Publish(in PublishInput) (*Version, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Version = strings.TrimSpace(in.Version)
	if err := validateNameVersion(in.Name, in.Version); err != nil {
		return nil, err
	}

	var info tarInfo
	if len(in.Artifact) > 0 {
		parsed, err := inspectTar(in.Artifact)
		if err != nil {
			return nil, err
		}
		info = parsed
	} else {
		// 允许仅登记元数据（黑盒测试/无归档场景）：摘要为空字节的 sha256。
		info = tarInfo{}
	}

	sum := sha256.Sum256(in.Artifact)
	digestHex := hex.EncodeToString(sum[:])
	digest := "sha256:" + digestHex
	objectPath := filepath.Join(s.objectsDir, digestHex+".tar")
	if _, err := os.Stat(objectPath); os.IsNotExist(err) {
		if err := os.WriteFile(objectPath, in.Artifact, 0o644); err != nil {
			return nil, fmt.Errorf("write object: %w", err)
		}
	}

	deps := append([]Dependency{}, info.Dependencies...)
	deps = append(deps, in.Dependencies...)

	var created *Version
	err := s.save(func() error {
		pkg, ok := s.State.Packages[in.Name]
		if !ok {
			pkg = &Package{Name: in.Name, CreatedAt: s.now(), Versions: map[string]*Version{}}
			s.State.Packages[in.Name] = pkg
		}
		if existing, exists := pkg.Versions[in.Version]; exists && existing != nil {
			return errAlreadyPublished
		}
		now := s.now()
		created = &Version{
			Name:         in.Name,
			Version:      in.Version,
			Digest:       digest,
			Size:         int64(len(in.Artifact)),
			Entries:      info.Entries,
			Filename:     in.Filename,
			Dependencies: deps,
			UploadedBy:   in.UploadedBy,
			CreatedAt:    now,
		}
		pkg.Versions[in.Version] = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// ObjectPath 返回摘要对应的归档文件路径。
func (s *Store) ObjectPath(digest string) string {
	hexPart := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(s.objectsDir, hexPart+".tar")
}

// VerifyDigest 重新计算磁盘对象的 sha256，用于下载前校验。
func (s *Store) VerifyDigest(v *Version) bool {
	raw, err := os.ReadFile(s.ObjectPath(v.Digest))
	if err != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	return "sha256:"+hex.EncodeToString(sum[:]) == v.Digest
}

// ListPackages 返回按名称排序的包摘要（默认剔除已删除版本）。
func (s *Store) ListPackages(includeDeleted bool) []*Package {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.State.Packages))
	for name := range s.State.Packages {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []*Package{}
	for _, name := range names {
		pkg := s.State.Packages[name]
		copied := &Package{Name: pkg.Name, CreatedAt: pkg.CreatedAt, Versions: map[string]*Version{}}
		for ver, v := range pkg.Versions {
			if v.Deleted && !includeDeleted {
				continue
			}
			copied.Versions[ver] = cloneVersion(v)
		}
		if len(copied.Versions) == 0 && !includeDeleted {
			continue
		}
		out = append(out, copied)
	}
	return out
}

// GetPackage 返回单个包的副本。
func (s *Store) GetPackage(name string) (*Package, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pkg, ok := s.State.Packages[name]
	if !ok {
		return nil, errPackageNotFound
	}
	copied := &Package{Name: pkg.Name, CreatedAt: pkg.CreatedAt, Versions: map[string]*Version{}}
	for ver, v := range pkg.Versions {
		copied.Versions[ver] = cloneVersion(v)
	}
	return copied, nil
}

// GetVersion 返回指定版本（version 为空时取最新语义/时间版本）。
func (s *Store) GetVersion(name, version string) (*Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pkg, ok := s.State.Packages[name]
	if !ok {
		return nil, errPackageNotFound
	}
	if version == "" || version == "latest" {
		var latest *Version
		for _, v := range pkg.Versions {
			if v.Deleted {
				continue
			}
			if latest == nil || v.CreatedAt.After(latest.CreatedAt) {
				latest = v
			}
		}
		if latest == nil {
			return nil, errVersionNotFound
		}
		return cloneVersion(latest), nil
	}
	v, ok := pkg.Versions[version]
	if !ok {
		return nil, errVersionNotFound
	}
	return cloneVersion(v), nil
}

func cloneVersion(v *Version) *Version {
	if v == nil {
		return nil
	}
	c := *v
	if v.Dependencies != nil {
		c.Dependencies = append([]Dependency{}, v.Dependencies...)
	}
	if v.DeletedAt != nil {
		t := *v.DeletedAt
		c.DeletedAt = &t
	}
	return &c
}

// RecordDownload 追加一条下载记录。
func (s *Store) RecordDownload(rec DownloadRecord) DownloadRecord {
	_ = s.save(func() error {
		rec.ID, _ = s.newID("dl", "download")
		if rec.At.IsZero() {
			rec.At = s.now()
		}
		if rec.Name == "" {
			rec.Name = rec.Package
		}
		s.State.Downloads = append(s.State.Downloads, rec)
		return nil
	})
	return rec
}

// AddBuild 登记一次构建/流水线运行。
func (s *Store) AddBuild(b BuildRecord) BuildRecord {
	_ = s.save(func() error {
		if b.ID == "" {
			b.ID, _ = s.newID("build", "build")
		} else {
			s.State.Counters["build"]++
		}
		if b.CreatedAt.IsZero() {
			b.CreatedAt = s.now()
		}
		if b.StartedAt.IsZero() {
			b.StartedAt = b.CreatedAt
		}
		if b.Name == "" {
			b.Name = b.Package
		}
		if b.Status == "" {
			b.Status = "running"
		}
		s.State.Builds = append(s.State.Builds, b)
		return nil
	})
	return b
}

// AddReference 手工登记一条包引用关系。
func (s *Store) AddReference(r Reference) Reference {
	_ = s.save(func() error {
		r.ID, _ = s.newID("ref", "reference")
		if r.CreatedAt.IsZero() {
			r.CreatedAt = s.now()
		}
		s.State.References = append(s.State.References, r)
		return nil
	})
	return r
}

// ListBuilds 返回构建记录（可按包名过滤），新记录在前。
func (s *Store) ListBuilds(packageName string) []BuildRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []BuildRecord{}
	for i := len(s.State.Builds) - 1; i >= 0; i-- {
		b := s.State.Builds[i]
		if packageName != "" && b.Package != packageName && b.Name != packageName {
			continue
		}
		out = append(out, b)
	}
	return out
}

// ListDownloads 返回下载记录（可按包名过滤），新记录在前。
func (s *Store) ListDownloads(packageName string) []DownloadRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []DownloadRecord{}
	for i := len(s.State.Downloads) - 1; i >= 0; i-- {
		d := s.State.Downloads[i]
		if packageName != "" && d.Package != packageName && d.Name != packageName {
			continue
		}
		out = append(out, d)
	}
	return out
}
