package manifest

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// ValidatePath ensures a manifest entry path is relative, slash separated and
// cannot escape the image root (no absolute paths, no ".." segments).
func ValidatePath(p string) error {
	if p == "" {
		return fmt.Errorf("path must not be empty")
	}
	if strings.HasPrefix(p, "/") || fs.ValidPath(p) == false {
		return fmt.Errorf("path must be a clean relative path: %q", p)
	}
	cleaned := path.Clean(p)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return fmt.Errorf("path must stay inside the image root: %q", p)
	}
	if cleaned != p {
		return fmt.Errorf("path must be normalized (use %q)", cleaned)
	}
	return nil
}

// RelativePath converts an OS path (relative to the image root) into the
// slash separated form used inside manifests.
func RelativePath(osRelative string) string {
	return path.Clean(strings.ReplaceAll(osRelative, "\\", "/"))
}
