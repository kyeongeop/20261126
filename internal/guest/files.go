package guest

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

func (s *Service) resolveGrant(rawDirectory string) (string, uint64, uint64, error) {
	rawDirectory = strings.TrimSpace(rawDirectory)
	if rawDirectory == "" {
		return "", 0, 0, newError("invalid_request", "directory is required", 400)
	}
	if strings.ContainsRune(rawDirectory, '\x00') {
		return "", 0, 0, newError("invalid_request", "directory contains an invalid character", 400)
	}

	candidate := filepath.FromSlash(rawDirectory)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(s.shareRoot, candidate)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, 0, newError("directory_not_found", "directory does not exist in the share root", 400)
		}
		return "", 0, 0, wrapError("directory_invalid", "could not resolve directory", 400, err)
	}
	if !withinRoot(s.shareRoot, resolved) {
		return "", 0, 0, newError("directory_outside_share_root", "directory must be inside the share root", 400)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", 0, 0, wrapError("directory_invalid", "could not inspect directory", 400, err)
	}
	if !info.IsDir() {
		return "", 0, 0, newError("directory_invalid", "directory is not a directory", 400)
	}
	relative, err := filepath.Rel(s.shareRoot, resolved)
	if err != nil || !withinRoot(s.shareRoot, resolved) {
		return "", 0, 0, newError("directory_outside_share_root", "directory must be inside the share root", 400)
	}
	dev, ino, _ := fileIdentity(info)
	return filepath.ToSlash(relative), dev, ino, nil
}

// syncDirectory verifies the stored directory identity. If the directory was
// moved inside the share root, its inode is located and the invitation path is
// updated. If it was deleted, moved outside the root, or replaced, access is
// denied until an administrator creates a new grant.
func (s *Service) syncDirectory(invitation Invitation) (string, error) {
	configured := filepath.Join(s.shareRoot, filepath.FromSlash(invitation.Directory))
	if current, ok := s.matchingDirectory(configured, invitation); ok {
		if err := s.store.updateInvitationDirectory(
			invitation.ID,
			current,
			invitation.DirectoryDev,
			invitation.DirectoryIno,
		); err != nil {
			return "", wrapError("internal_error", "could not update directory grant", 500, err)
		}
		return current, nil
	}

	current, err := s.findDirectoryByIdentity(invitation.DirectoryDev, invitation.DirectoryIno)
	if err != nil {
		return "", wrapError("internal_error", "could not inspect share root", 500, err)
	}
	if current == "" {
		return "", ErrDirectoryMissing
	}
	if err := s.store.updateInvitationDirectory(
		invitation.ID,
		current,
		invitation.DirectoryDev,
		invitation.DirectoryIno,
	); err != nil {
		return "", wrapError("internal_error", "could not update directory grant", 500, err)
	}
	return current, nil
}

func (s *Service) matchingDirectory(candidate string, invitation Invitation) (string, bool) {
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil || !withinRoot(s.shareRoot, resolved) {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", false
	}
	if invitation.DirectoryDev != 0 || invitation.DirectoryIno != 0 {
		dev, ino, ok := fileIdentity(info)
		if !ok || dev != invitation.DirectoryDev || ino != invitation.DirectoryIno {
			return "", false
		}
	}
	relative, err := filepath.Rel(s.shareRoot, resolved)
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(relative), true
}

func (s *Service) findDirectoryByIdentity(dev, ino uint64) (string, error) {
	if dev == 0 && ino == 0 {
		return "", nil
	}
	var match string
	err := filepath.WalkDir(s.shareRoot, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if current == s.shareRoot {
				return walkErr
			}
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		entryDev, entryIno, ok := fileIdentity(info)
		if !ok || entryDev != dev || entryIno != ino {
			return nil
		}
		if match != "" {
			return fmt.Errorf("directory identity is ambiguous")
		}
		relative, err := filepath.Rel(s.shareRoot, current)
		if err != nil {
			return nil
		}
		match = filepath.ToSlash(relative)
		return nil
	})
	if err != nil {
		return "", err
	}
	return match, nil
}

func (s *Service) ListDirectory(session GuestSession, rawPath string) ([]EntryView, error) {
	relative, resolved, err := s.resolveGuestPath(session.RootPath, rawPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, mapPathError(err)
	}
	if !info.IsDir() {
		return nil, newError("not_a_directory", "requested path is not a directory", 400)
	}

	root, err := os.OpenRoot(session.RootPath)
	if err != nil {
		return nil, wrapError("internal_error", "could not open authorized directory", 500, err)
	}
	defer root.Close()
	dir, err := root.Open(relative)
	if err != nil {
		return nil, mapPathError(err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, wrapError("internal_error", "could not list directory", 500, err)
	}

	result := make([]EntryView, 0, len(entries))
	for _, entry := range entries {
		view := EntryView{Name: entry.Name(), Type: entryType(entry.Type())}
		if info, err := entry.Info(); err == nil {
			view.Size = info.Size()
			view.ModifiedAt = info.ModTime().UTC()
		}
		result = append(result, view)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (s *Service) OpenGuestFile(session GuestSession, rawPath string) (*os.File, os.FileInfo, error) {
	relative, resolved, err := s.resolveGuestPath(session.RootPath, rawPath)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, nil, mapPathError(err)
	}
	if info.IsDir() {
		return nil, nil, ErrNotAFile
	}

	root, err := os.OpenRoot(session.RootPath)
	if err != nil {
		return nil, nil, wrapError("internal_error", "could not open authorized directory", 500, err)
	}
	defer root.Close()
	file, err := root.Open(relative)
	if err != nil {
		return nil, nil, mapPathError(err)
	}
	info, err = file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, mapPathError(err)
	}
	if info.IsDir() {
		file.Close()
		return nil, nil, ErrNotAFile
	}
	return file, info, nil
}

func (s *Service) resolveGuestPath(rootPath, rawPath string) (relative, resolved string, err error) {
	relative, err = cleanRelativePath(rawPath)
	if err != nil {
		return "", "", err
	}
	resolved, err = filepath.EvalSymlinks(filepath.Join(rootPath, filepath.FromSlash(relative)))
	if err != nil {
		return "", "", mapPathError(err)
	}
	if !withinRoot(rootPath, resolved) {
		return "", "", ErrPathOutsideRoot
	}
	return relative, resolved, nil
}

func cleanRelativePath(rawPath string) (string, error) {
	if strings.ContainsRune(rawPath, '\x00') {
		return "", ErrPathOutsideRoot
	}
	if rawPath == "" {
		return ".", nil
	}
	if strings.HasPrefix(rawPath, "/") {
		return "", ErrPathOutsideRoot
	}
	clean := path.Clean(rawPath)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", ErrPathOutsideRoot
	}
	if clean == "." {
		return ".", nil
	}
	return clean, nil
}

func withinRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func mapPathError(err error) error {
	if os.IsNotExist(err) {
		return ErrFileNotFound
	}
	if errors.Is(err, os.ErrPermission) {
		return ErrPathOutsideRoot
	}
	return wrapError("path_access_failed", "could not access path", 400, err)
}

func entryType(mode os.FileMode) string {
	switch {
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode.IsRegular():
		return "file"
	default:
		return "other"
	}
}
