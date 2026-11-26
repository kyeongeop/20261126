package sync

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrContentMismatch means a package cannot match its manifest entry (wrong
// size or digest) and must be reported as replaced, not retried.
var ErrContentMismatch = errors.New("package content mismatch")

// PackageStatus classifies what was observed for a single manifest entry.
type PackageStatus string

const (
	// StatusOK: present on disk and digest/size match the manifest.
	StatusOK PackageStatus = "ok"
	// StatusMissing: declared by the manifest but absent in the image.
	StatusMissing PackageStatus = "missing"
	// StatusReplaced: present but digest or size differs from the manifest.
	StatusReplaced PackageStatus = "replaced"
	// StatusDuplicate: same package path appears more than once on disk
	// (case/normalization collision) or is listed repeatedly in a bundle.
	StatusDuplicate PackageStatus = "duplicate"
)

// PackageFinding records the verification result of one package.
type PackageFinding struct {
	Path     string        `json:"path"`
	Status   PackageStatus `json:"status"`
	Expected string        `json:"expectedSha256,omitempty"`
	Actual   string        `json:"actualSha256,omitempty"`
	Size     int64         `json:"size,omitempty"`
	Detail   string        `json:"detail,omitempty"`
}

// Report is the full verification / synchronization result. Problem lists
// are kept separate so missing, duplicated and replaced packages can each be
// reviewed and handled independently.
type Report struct {
	ImageID     string           `json:"imageId"`
	GeneratedAt string           `json:"generatedAt"`
	TotalListed int              `json:"totalListed"`
	Verified    int              `json:"verified"`
	Missing     []PackageFinding `json:"missing"`
	Duplicated  []PackageFinding `json:"duplicated"`
	Replaced    []PackageFinding `json:"replaced"`
	// Extra packages exist on disk but are not declared in the manifest.
	Extra        []PackageFinding `json:"extra,omitempty"`
	ResumedCount int              `json:"resumedCount"`
	RetriedCount int              `json:"retriedCount"`
}

// NewReport creates an empty report for an image.
func NewReport(imageID string) *Report {
	return &Report{
		ImageID:     imageID,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Missing:     []PackageFinding{},
		Duplicated:  []PackageFinding{},
		Replaced:    []PackageFinding{},
		Extra:       []PackageFinding{},
	}
}

// Problems returns true when any anomaly was recorded.
func (r *Report) Problems() bool {
	return len(r.Missing)+len(r.Duplicated)+len(r.Replaced)+len(r.Extra) > 0
}

// Marshal renders the report as indented JSON.
func (r *Report) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
