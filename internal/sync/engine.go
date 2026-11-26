package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"mirrorsync/internal/manifest"
	"mirrorsync/internal/source"
)

// DefaultMaxRetries is the number of additional attempts per package after
// the first one fails.
const DefaultMaxRetries = 3

// Engine synchronizes packages from a Source into a local destination
// directory while persisting progress and verifying every byte.
type Engine struct {
	Src        source.Source
	DestDir    string
	MaxRetries int
	// InspectDuplicates, when set, scans the source for repeated package
	// entries before any transfer begins.
	InspectDuplicates func() ([]source.DuplicateEntry, error)
	// OnProgress, when set, receives the package path and cumulative bytes.
	OnProgress func(path string, done, total int64)
}

// Result bundles the report with the checkpoint used during the run.
type Result struct {
	Report *Report
}

// Run downloads every manifest entry that is missing or incomplete and
// verifies all entries, including packages that were already on disk.
func (e *Engine) Run(ctx context.Context, m *manifest.Manifest) (*Result, error) {
	if e.MaxRetries <= 0 {
		e.MaxRetries = DefaultMaxRetries
	}
	if err := os.MkdirAll(e.DestDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating destination: %w", err)
	}
	cp, err := loadCheckpoint(e.DestDir, m.ImageID)
	if err != nil {
		return nil, err
	}
	report := NewReport(m.ImageID)
	report.TotalListed = len(m.Packages)

	if e.InspectDuplicates != nil {
		dupes, dupErr := e.InspectDuplicates()
		if dupErr != nil {
			return nil, dupErr
		}
		for _, d := range dupes {
			report.Duplicated = append(report.Duplicated, PackageFinding{
				Path: d.Path, Status: StatusDuplicate,
				Detail: fmt.Sprintf("path appears %d times in transfer source", d.Count),
			})
		}
	}

	for _, entry := range m.Packages {
		if ctxErr := ctx.Err(); ctxErr != nil {
			_ = cp.save(e.DestDir)
			return nil, ctxErr
		}
		finding, progress, resumed, retried, err := e.syncOne(ctx, entry, cp)
		if resumed {
			report.ResumedCount++
		}
		if retried {
			report.RetriedCount++
		}
		if err != nil {
			// Persist progress before surfacing the failure so a rerun
			// continues from the last byte rather than starting over.
			_ = cp.save(e.DestDir)
			return nil, fmt.Errorf("package %q: %w", entry.Path, err)
		}
		cp.Packages[entry.Path] = progress
		if err := cp.save(e.DestDir); err != nil {
			return nil, err
		}
		switch finding.Status {
		case StatusOK:
			report.Verified++
		case StatusMissing:
			report.Missing = append(report.Missing, finding)
		case StatusReplaced:
			report.Replaced = append(report.Replaced, finding)
		case StatusDuplicate:
			report.Duplicated = append(report.Duplicated, finding)
		}
	}

	extras, err := e.findExtra(m)
	if err != nil {
		return nil, err
	}
	report.Extra = extras
	return &Result{Report: report}, nil
}

// syncOne transfers (if needed) and verifies one entry. It returns the
// finding together with the progress to checkpoint.
func (e *Engine) syncOne(ctx context.Context, entry manifest.Entry, cp *Checkpoint) (PackageFinding, PackageProgress, bool, bool, error) {
	progress := cp.Packages[entry.Path]
	progress.Path = entry.Path
	full := filepath.Join(e.DestDir, filepath.FromSlash(entry.Path))
	resumed := false
	retried := false

	// A previously completed checkpoint is still re-verified below; never
	// trust the state file on its own.
	needDownload := !progress.Done
	if !needDownload {
		if info, statErr := os.Stat(full); statErr != nil || info.Size() != entry.Size {
			needDownload = true
			progress.Done = false
		}
	}

	if needDownload {
		if progress.BytesDone > 0 {
			resumed = true
		}
		var transferErr error
		var attempts int
		progress, attempts, transferErr = e.transferWithRetry(ctx, entry, full, progress)
		retried = attempts > 1
		if transferErr != nil {
			if errors.Is(transferErr, source.ErrNotFound) {
				// A package the source cannot provide is reported and the
				// run continues so the rest of the image is processed.
				return PackageFinding{Path: entry.Path, Status: StatusMissing,
					Expected: entry.SHA256, Detail: "not available in transfer source"}, progress, resumed, retried, nil
			}
			if errors.Is(transferErr, ErrContentMismatch) {
				actual, size, _ := hashLocal(full)
				return PackageFinding{Path: entry.Path, Status: StatusReplaced,
					Expected: entry.SHA256, Actual: actual, Size: size,
					Detail: transferErr.Error()}, progress, resumed, retried, nil
			}
			return PackageFinding{}, progress, resumed, retried, transferErr
		}
	}

	actual, size, err := hashLocal(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PackageFinding{Path: entry.Path, Status: StatusMissing,
				Expected: entry.SHA256}, progress, resumed, retried, nil
		}
		return PackageFinding{}, progress, resumed, retried, err
	}
	if actual != entry.SHA256 || size != entry.Size {
		return PackageFinding{
			Path: entry.Path, Status: StatusReplaced,
			Expected: entry.SHA256, Actual: actual, Size: size,
			Detail: fmt.Sprintf("expected size %d digest %s", entry.Size, entry.SHA256),
		}, progress, resumed, retried, nil
	}
	progress.Done = true
	progress.BytesDone = size
	progress.TotalBytes = entry.Size
	return PackageFinding{Path: entry.Path, Status: StatusOK, Actual: actual, Size: size}, progress, resumed, retried, nil
}

// transferWithRetry restarts a failed package from its checkpoint offset.
func (e *Engine) transferWithRetry(ctx context.Context, entry manifest.Entry, full string, progress PackageProgress) (PackageProgress, int, error) {
	var lastErr error
	for attempt := 0; attempt <= e.MaxRetries; attempt++ {
		if attempt > 0 {
			progress.Attempts = attempt
		}
		done, err := e.transferOnce(ctx, entry, full, progress.BytesDone)
		progress.BytesDone = done
		if err == nil {
			progress.TotalBytes = entry.Size
			progress.Done = true
			return progress, attempt + 1, nil
		}
		lastErr = err
		if ctxErr := ctx.Err(); ctxErr != nil {
			return progress, attempt + 1, ctxErr
		}
		if errors.Is(err, source.ErrNotFound) {
			return progress, attempt + 1, err
		}
		if errors.Is(err, ErrContentMismatch) {
			return progress, attempt + 1, err
		}
	}
	return progress, e.MaxRetries + 1, fmt.Errorf("transfer failed after %d attempts: %w", e.MaxRetries+1, lastErr)
}

// transferOnce performs one (possibly resuming) fetch and returns bytes on
// disk afterwards.
func (e *Engine) transferOnce(ctx context.Context, entry manifest.Entry, full string, offset int64) (int64, error) {
	rc, total, err := e.Src.Open(ctx, entry.Path, offset)
	if err != nil {
		return offset, err
	}
	defer rc.Close()

	// A backend that ignores Range returns the whole file: restart at zero.
	if offset > 0 {
		honored := true
		if h, ok := rc.(source.OffsetHonorer); ok {
			honored = h.HonoredOffset()
		}
		if !honored {
			offset = 0
		}
	}
	// A source whose package size differs from the manifest cannot ever
	// verify successfully; classify it as replaced rather than retrying.
	if total >= 0 && total != entry.Size {
		return offset, fmt.Errorf("%w: source size %d does not match manifest size %d",
			ErrContentMismatch, total, entry.Size)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return offset, err
	}
	flag := os.O_CREATE | os.O_WRONLY
	if offset == 0 {
		flag |= os.O_TRUNC
	}
	out, err := os.OpenFile(full, flag, 0o644)
	if err != nil {
		return offset, err
	}
	if offset > 0 {
		if _, err := out.Seek(offset, io.SeekStart); err != nil {
			out.Close()
			return offset, err
		}
	}
	written := offset
	buf := make([]byte, 64*1024)
	for {
		n, readErr := rc.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				return written, werr
			}
			written += int64(n)
			if written > entry.Size {
				out.Close()
				return written, fmt.Errorf("%w: package exceeds manifest size %d", ErrContentMismatch, entry.Size)
			}
			if e.OnProgress != nil {
				e.OnProgress(entry.Path, written, entry.Size)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			out.Close()
			return written, readErr
		}
	}
	if err := out.Close(); err != nil {
		return written, err
	}
	if written != entry.Size {
		return written, fmt.Errorf("%w: short transfer: got %d bytes, expected %d",
			ErrContentMismatch, written, entry.Size)
	}
	return written, nil
}
