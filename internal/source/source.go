package source

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned when a source does not contain the requested path.
var ErrNotFound = errors.New("package not found in source")

// ReadCloserAt is a reader whose Close must be called when done. The same
// interface is implemented by the different backends so the sync engine can
// resume partially transferred packages uniformly.
type ReadCloserAt interface {
	io.ReadCloser
}

// OffsetHonorer is implemented by readers that actually started at the
// requested offset. Backends that ignore resume offsets (for example an HTTP
// server replying 200 to a Range request) omit it, telling the engine to
// truncate the destination and restart from byte zero.
type OffsetHonorer interface {
	HonoredOffset() bool
}

// Source is a read-only package repository used by the sync engine.
type Source interface {
	// Open returns a reader positioned at byte offset of the named package.
	// Implementations must support offset 0 and, for resumable transfers,
	// arbitrary offsets.
	Open(ctx context.Context, path string, offset int64) (ReadCloserAt, int64, error)
}
