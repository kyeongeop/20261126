package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"path"
	"strings"
)

type tarInfo struct {
	Entries      int
	Dependencies []Dependency
}

// inspectTar 校验 tar 可读、统计普通文件数量，并尝试从常见清单文件解析依赖关系。
func inspectTar(artifact []byte) (tarInfo, error) {
	reader := tar.NewReader(bytes.NewReader(artifact))
	info := tarInfo{}
	manifestDeps := []Dependency{}
	txtDeps := []Dependency{}

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return info, errInvalidTar
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			info.Entries++
		}
		base := manifestBaseName(header.Name)
		if base == "" {
			continue
		}
		limited := io.LimitReader(reader, 4<<20)
		raw, err := io.ReadAll(limited)
		if err != nil {
			return info, errInvalidTar
		}
		switch base {
		case "package.json", "pkg.json":
			if deps := parsePackageJSONDeps(raw); len(deps) > 0 {
				manifestDeps = append(manifestDeps, withSource(deps, "package.json")...)
			}
		case "manifest.json":
			if deps := parseManifestJSONDeps(raw); len(deps) > 0 {
				manifestDeps = append(manifestDeps, withSource(deps, "manifest.json")...)
			}
		case "dependencies.txt", "deps.txt", "requirements.txt":
			txtDeps = append(txtDeps, withSource(parseTextDeps(raw), base)...)
		}
	}

	seen := map[string]bool{}
	for _, dep := range append(manifestDeps, txtDeps...) {
		key := dep.Package + "\x00" + dep.Constraint
		if dep.Package == "" || seen[key] {
			continue
		}
		seen[key] = true
		info.Dependencies = append(info.Dependencies, dep)
	}
	return info, nil
}

func withSource(deps []Dependency, source string) []Dependency {
	for i := range deps {
		if deps[i].Source == "" {
			deps[i].Source = source
		}
	}
	return deps
}

// manifestBaseName 允许清单位于 tar 根目录或唯一的一层顶层目录内。
func manifestBaseName(name string) string {
	clean := path.Clean(strings.TrimPrefix(name, "./"))
	parts := strings.Split(clean, "/")
	if len(parts) == 1 {
		return parts[0]
	}
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func parsePackageJSONDeps(raw []byte) []Dependency {
	var doc struct {
		Dependencies     map[string]string `json:"dependencies"`
		PeerDependencies map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	deps := map[string]string{}
	for k, v := range doc.Dependencies {
		deps[k] = v
	}
	for k, v := range doc.PeerDependencies {
		if _, exists := deps[k]; !exists {
			deps[k] = v
		}
	}
	return mapToDeps(deps)
}

func parseManifestJSONDeps(raw []byte) []Dependency {
	var doc struct {
		Dependencies json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Dependencies) == 0 {
		return nil
	}
	var asMap map[string]string
	if err := json.Unmarshal(doc.Dependencies, &asMap); err == nil {
		return mapToDeps(asMap)
	}
	var asList []string
	if err := json.Unmarshal(doc.Dependencies, &asList); err == nil {
		deps := []Dependency{}
		for _, item := range asList {
			if name, constraint := splitNameConstraint(item); name != "" {
				deps = append(deps, Dependency{Package: name, Constraint: constraint})
			}
		}
		return deps
	}
	var asObjs []struct {
		Name       string `json:"name"`
		Package    string `json:"package"`
		Version    string `json:"version"`
		Constraint string `json:"constraint"`
	}
	if err := json.Unmarshal(doc.Dependencies, &asObjs); err != nil {
		return nil
	}
	deps := []Dependency{}
	for _, obj := range asObjs {
		name := obj.Name
		if name == "" {
			name = obj.Package
		}
		constraint := obj.Constraint
		if constraint == "" {
			constraint = obj.Version
		}
		if name != "" {
			deps = append(deps, Dependency{Package: name, Constraint: constraint})
		}
	}
	return deps
}

func mapToDeps(m map[string]string) []Dependency {
	deps := make([]Dependency, 0, len(m))
	for name, constraint := range m {
		deps = append(deps, Dependency{Package: name, Constraint: constraint})
	}
	return deps
}

func parseTextDeps(raw []byte) []Dependency {
	deps := []Dependency{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexAny(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if name, constraint := splitNameConstraint(line); name != "" {
			deps = append(deps, Dependency{Package: name, Constraint: constraint})
		}
	}
	return deps
}

// splitNameConstraint 解析 "name@>=1.0"、"name==1.2"、"name 1.2"、"name@1.0"。
func splitNameConstraint(item string) (string, string) {
	item = strings.TrimSpace(item)
	for _, sep := range []string{"==", ">=", "<=", "~=", "@", " "} {
		if idx := strings.Index(item, sep); idx > 0 {
			name := strings.TrimSpace(item[:idx])
			constraint := strings.TrimSpace(item[idx+len(sep):])
			if packageNamePattern.MatchString(name) {
				return name, constraint
			}
		}
	}
	if packageNamePattern.MatchString(item) {
		return item, ""
	}
	return "", ""
}
