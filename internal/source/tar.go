package source

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
)

// TarSource reads packages from an uncompressed tar archive (typical payload
// of an offline file bundle). Every Open call re-scans the archive; tar is a
// sequential format, but seeking to the entry and skipping the resume offset
// keeps large packages resumable without extracting everything first.
type TarSource struct {
	ArchivePath string
}

// NewTarSource validates that the archive can be opened.
func NewTarSource(archivePath string) (*TarSource, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return &TarSource{ArchivePath: archivePath}, nil
}

// Open locates path in the tar and returns its content starting at offset.
func (t *TarSource) Open(_ context.Context, path string, offset int64) (ReadCloserAt, int64, error) {
	f, err := os.Open(t.ArchivePath)
	if err != nil {
		return nil, 0, err
	}
	tr := tar.NewReader(f)
	for {
		hdr, hdrErr := tr.Next()
		if hdrErr == io.EOF {
			break
		}
		if hdrErr != nil {
			f.Close()
			return nil, 0, fmt.Errorf("reading tar archive: %w", hdrErr)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if hdr.Name != path {
			continue
		}
		if offset > hdr.Size {
			f.Close()
			return nil, 0, fmt.Errorf("resume offset %d exceeds size %d of %s", offset, hdr.Size, path)
		}
		if offset > 0 {
			if _, skipErr := io.CopyN(io.Discard, tr, offset); skipErr != nil {
				f.Close()
				return nil, 0, fmt.Errorf("skipping to resume offset of %s: %w", path, skipErr)
			}
		}
		return &tarEntryReader{reader: tr, file: f, honored: offset > 0}, hdr.Size, nil
	}
	f.Close()
	return nil, 0, fmt.Errorf("%w: %s", ErrNotFound, path)
}

// tarEntryReader closes both the tar stream and the underlying file.
type tarEntryReader struct {
	reader  io.Reader
	file    io.Closer
	honored bool
}

func (r *tarEntryReader) Read(p []byte) (int, error) { return r.reader.Read(p) }

func (r *tarEntryReader) Close() error { return r.file.Close() }

func (r *tarEntryReader) HonoredOffset() bool { return r.honored }
