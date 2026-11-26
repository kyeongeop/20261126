package source

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"mirrorsync/internal/manifest"
)

// DirSource serves packages from a local directory (e.g. a mounted USB drive
// or a previously extracted bundle).
type DirSource struct {
	Root string
}

// NewDirSource checks that root exists and is a directory.
func NewDirSource(root string) (*DirSource, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source root is not a directory: %s", root)
	}
	return &DirSource{Root: root}, nil
}

// Open seeks to offset within the requested package file.
func (d *DirSource) Open(_ context.Context, path string, offset int64) (ReadCloserAt, int64, error) {
	if err := manifest.ValidatePath(path); err != nil {
		return nil, 0, err
	}
	full := filepath.Join(d.Root, filepath.FromSlash(path))
	info, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("not a regular file: %s", path)
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, 0, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, 0, err
		}
	}
	return &fileReader{File: f, honored: offset > 0}, info.Size(), nil
}

type fileReader struct {
	*os.File
	honored bool
}

func (r *fileReader) HonoredOffset() bool { return r.honored }
