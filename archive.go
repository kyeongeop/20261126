package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// SHA256Prefix prefixes every digest produced by this package.
const SHA256Prefix = "sha256:"

// DigestBytes returns the "sha256:<hex>" digest of b.
func DigestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return SHA256Prefix + hex.EncodeToString(sum[:])
}

// DigestReader copies r into h and returns the "sha256:<hex>" digest of all
// bytes read, together with the byte count.
func DigestReader(r io.Reader) (digest string, size int64, err error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", n, err
	}
	return SHA256Prefix + hex.EncodeToString(h.Sum(nil)), n, nil
}

// NormalizeSHA256 accepts "sha256:<hex>", "sha256-<hex|base64>" or a bare
// 64-char hex string and returns lowercase "sha256:<hex>". It returns false
// when the value does not encode a sha256 digest (including sha512 SRI).
func NormalizeSHA256(in string) (string, bool) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", false
	}
	lower := strings.ToLower(s)

	switch {
	case strings.HasPrefix(lower, "sha256:"):
		raw := s[len("sha256:"):]
		return hexDigest(raw)
	case strings.HasPrefix(lower, "sha256-"):
		raw := s[len("sha256-"):]
		if d, ok := hexDigest(raw); ok {
			return d, true
		}
		dec, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(dec) != sha256.Size {
			return "", false
		}
		return SHA256Prefix + hex.EncodeToString(dec), true
	default:
		return hexDigest(s)
	}
}

func hexDigest(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) != hex.EncodedLen(sha256.Size) {
		return "", false
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != sha256.Size {
		return "", false
	}
	return SHA256Prefix + hex.EncodeToString(b), true
}

// TarEntry is one file to place in an archive.
type TarEntry struct {
	Name    string
	Content []byte
	Mode    int64
}

// BuildTar creates a deterministic, well-formed uncompressed tar from files.
// Entries are sorted by name and use a fixed timestamp so digests are stable.
func BuildTar(files map[string]string) ([]byte, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]TarEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, TarEntry{Name: name, Content: []byte(files[name]), Mode: 0o644})
	}
	return BuildTarEntries(entries)
}

// BuildTarEntries builds a tar from explicit entries.
func BuildTarEntries(entries []TarEntry) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	epoch := time.Unix(0, 0).UTC()
	for _, e := range entries {
		clean, err := SafeTarPath(e.Name)
		if err != nil {
			return nil, err
		}
		mode := e.Mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{
			Name:    clean,
			Mode:    mode,
			Size:    int64(len(e.Content)),
			ModTime: epoch,
			Uid:     0,
			Gid:     0,
			Uname:   "",
			Gname:   "",
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("tar header %q: %w", e.Name, err)
		}
		if _, err := tw.Write(e.Content); err != nil {
			return nil, fmt.Errorf("tar content %q: %w", e.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	return buf.Bytes(), nil
}

// SafeTarPath validates an archive entry name against path traversal and
// absolute paths, returning a cleaned slash-separated name.
func SafeTarPath(name string) (string, error) {
	n := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if n == "" {
		return "", fmt.Errorf("empty tar entry name")
	}
	if path.IsAbs(n) || strings.HasPrefix(n, "/") {
		return "", fmt.Errorf("absolute tar entry path not allowed: %q", name)
	}
	clean := path.Clean(n)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("tar entry escapes package root: %q", name)
	}
	return clean, nil
}

// TarInfo summarizes a verified archive.
type TarInfo struct {
	Entries []string
	Files   int
}

// VerifyTar reads r as a tar stream and validates every entry path. It does
// not extract anything; callers that need bytes can iterate the returned
// reader separately. Here it returns the entry list for inspection.
func VerifyTar(r io.Reader) (*TarInfo, error) {
	tr := tar.NewReader(r)
	info := &TarInfo{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			if _, err := SafeTarPath(hdr.Name); err != nil {
				return nil, err
			}
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, fmt.Errorf("tar entry %q: %w", hdr.Name, err)
			}
			info.Files++
			info.Entries = append(info.Entries, hdr.Name)
		}
	}
	sort.Strings(info.Entries)
	return info, nil
}
