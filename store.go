package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	errRepairRequiresAdmin = errors.New("only administrators may publish repair versions")
	errAdminRepairOnly     = errors.New("administrators may only publish repair versions")
	errRepairBaseNotFound  = errors.New("repair target version does not exist")
	errInvalidArchive      = errors.New("artifact is not a valid tar archive")
)

type Store struct {
	dataDir    string
	objectDir  string
	releaseDir string
	tempDir    string
	key        *signer
	mu         sync.RWMutex
}

type PublishRequest struct {
	Name      string
	Version   string
	Artifact  io.Reader
	Publisher Publisher
	Repair    *RepairInfo
}

func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		dataDir:    dataDir,
		objectDir:  filepath.Join(dataDir, "objects"),
		releaseDir: filepath.Join(dataDir, "releases"),
		tempDir:    filepath.Join(dataDir, "tmp"),
	}
	for _, dir := range []string{s.dataDir, s.objectDir, s.releaseDir, s.tempDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}
	key, err := loadSigner(dataDir)
	if err != nil {
		return nil, err
	}
	s.key = key
	return s, nil
}

func (s *Store) Publish(req PublishRequest) (Release, error) {
	if err := validateIdentity(req.Name, req.Version); err != nil {
		return Release{}, err
	}
	if req.Artifact == nil {
		return Release{}, errInvalidArchive
	}
	if req.Repair == nil && req.Publisher.Role != rolePublisher {
		if req.Publisher.Role == roleAdmin {
			return Release{}, errAdminRepairOnly
		}
		return Release{}, errForbidden
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	releasePath := s.releasePath(req.Name, req.Version)
	if _, err := os.Stat(releasePath); err == nil {
		return Release{}, errVersionExists
	} else if !os.IsNotExist(err) {
		return Release{}, fmt.Errorf("check version: %w", err)
	}

	if req.Repair != nil {
		if err := s.checkRepair(req); err != nil {
			return Release{}, err
		}
	}

	tempFile, err := os.CreateTemp(s.tempDir, "upload-*.tar")
	if err != nil {
		return Release{}, fmt.Errorf("create upload temp file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(tempFile, hasher), req.Artifact)
	if err == nil {
		err = tempFile.Sync()
	}
	if closeErr := tempFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return Release{}, fmt.Errorf("store upload: %w", err)
	}
	if size == 0 {
		return Release{}, errInvalidArchive
	}

	entries, err := inspectTar(tempPath)
	if err != nil {
		return Release{}, err
	}
	digestHex := hex.EncodeToString(hasher.Sum(nil))
	if err := s.installObject(tempPath, digestHex, size); err != nil {
		return Release{}, err
	}

	now := time.Now().UTC()
	release := Release{
		SchemaVersion: 1,
		Name:          req.Name,
		Version:       req.Version,
		ContentDigest: "sha256:" + digestHex,
		Publisher:     req.Publisher,
		Archive: ArchiveInfo{
			Format:  "tar",
			Size:    size,
			Entries: entries,
		},
		Repair:      req.Repair,
		PublishedAt: now,
	}
	release.Publisher.PublishedAt = now
	release.Signature, err = s.key.sign(release, now)
	if err != nil {
		return Release{}, err
	}
	encoded, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		return Release{}, fmt.Errorf("encode release: %w", err)
	}
	if err := s.writeExclusive(releasePath, encoded); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Release{}, errVersionExists
		}
		return Release{}, fmt.Errorf("write release metadata: %w", err)
	}
	return release, nil
}

func (s *Store) checkRepair(req PublishRequest) error {
	if req.Publisher.Role != roleAdmin {
		return errRepairRequiresAdmin
	}
	if req.Repair.OfVersion == req.Version {
		return errVersionExists
	}
	if err := validateIdentity(req.Name, req.Repair.OfVersion); err != nil {
		return errInvalidVersion
	}
	if _, err := s.releaseLocked(req.Name, req.Repair.OfVersion); err != nil {
		if os.IsNotExist(err) {
			return errRepairBaseNotFound
		}
		return err
	}
	return nil
}

func (s *Store) installObject(tempPath, digestHex string, size int64) error {
	objectPath := filepath.Join(s.objectDir, digestHex+".tar")
	if info, err := os.Stat(objectPath); err == nil {
		if info.Size() != size {
			return fmt.Errorf("content-addressed object %s has unexpected size", digestHex)
		}
		actual, err := hashFile(objectPath)
		if err != nil {
			return err
		}
		if actual != digestHex {
			return fmt.Errorf("content-addressed object %s is corrupted", digestHex)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check content object: %w", err)
	}
	if err := os.Link(tempPath, objectPath); err != nil {
		if os.IsExist(err) {
			return s.installObject(tempPath, digestHex, size)
		}
		return fmt.Errorf("install content object: %w", err)
	}
	return nil
}

func (s *Store) writeExclusive(destination string, data []byte) error {
	tempFile, err := os.CreateTemp(s.tempDir, "metadata-*.json")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if err := os.Link(tempPath, destination); err != nil {
		return err
	}
	return nil
}

func (s *Store) releasePath(name, version string) string {
	return filepath.Join(s.releaseDir, name, version+".json")
}

func (s *Store) releaseLocked(name, version string) (Release, error) {
	data, err := os.ReadFile(s.releasePath(name, version))
	if err != nil {
		return Release{}, err
	}
	var release Release
	if err := json.Unmarshal(data, &release); err != nil {
		return Release{}, fmt.Errorf("decode release metadata: %w", err)
	}
	if release.Name != name || release.Version != version {
		return Release{}, fmt.Errorf("release metadata does not match its path")
	}
	return release, nil
}

func (s *Store) Release(name, version string) (Release, error) {
	if err := validateIdentity(name, version); err != nil {
		return Release{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.releaseLocked(name, version)
}

func (s *Store) List() ([]Release, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var releases []Release
	packageDirs, err := os.ReadDir(s.releaseDir)
	if err != nil {
		return nil, err
	}
	for _, packageDir := range packageDirs {
		if packageDir.IsDir() {
			files, err := os.ReadDir(filepath.Join(s.releaseDir, packageDir.Name()))
			if err != nil {
				return nil, err
			}
			for _, file := range files {
				if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
					continue
				}
				version := strings.TrimSuffix(file.Name(), ".json")
				release, err := s.releaseLocked(packageDir.Name(), version)
				if err != nil {
					return nil, err
				}
				releases = append(releases, release)
			}
		}
	}
	sort.Slice(releases, func(i, j int) bool {
		if releases[i].PublishedAt.Equal(releases[j].PublishedAt) {
			if releases[i].Name == releases[j].Name {
				return releases[i].Version < releases[j].Version
			}
			return releases[i].Name < releases[j].Name
		}
		return releases[i].PublishedAt.After(releases[j].PublishedAt)
	})
	return releases, nil
}

func hashFile(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func inspectTar(filename string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	reader := tar.NewReader(f)
	entries := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("%w: %v", errInvalidArchive, err)
		}
		if !safeArchivePath(header.Name) {
			return 0, fmt.Errorf("%w: unsafe path %q", errInvalidArchive, header.Name)
		}
		entries++
	}
	if entries == 0 {
		return 0, errInvalidArchive
	}
	return entries, nil
}

func safeArchivePath(name string) bool {
	if name == "" || path.IsAbs(name) || filepath.IsAbs(name) || strings.ContainsRune(name, '\\') {
		return false
	}
	cleaned := path.Clean(name)
	return cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}
