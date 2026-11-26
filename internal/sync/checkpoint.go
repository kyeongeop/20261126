package sync

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// checkpointName is the state file kept inside the destination image.
const checkpointName = ".mirrorsync-state.json"

// PackageProgress records how far one package transfer has progressed.
type PackageProgress struct {
	Path       string `json:"path"`
	BytesDone  int64  `json:"bytesDone"`
	TotalBytes int64  `json:"totalBytes"`
	Done       bool   `json:"done"`
	Attempts   int    `json:"attempts"`
}

// Checkpoint persists transfer progress so a restarted run resumes instead of
// re-downloading everything.
type Checkpoint struct {
	ImageID  string                     `json:"imageId"`
	Packages map[string]PackageProgress `json:"packages"`
}

func newCheckpoint(imageID string) *Checkpoint {
	return &Checkpoint{ImageID: imageID, Packages: map[string]PackageProgress{}}
}

func checkpointPath(destDir string) string {
	return filepath.Join(destDir, checkpointName)
}

// loadCheckpoint returns an empty checkpoint when no state file exists yet.
func loadCheckpoint(destDir, imageID string) (*Checkpoint, error) {
	data, err := os.ReadFile(checkpointPath(destDir))
	if os.IsNotExist(err) {
		return newCheckpoint(imageID), nil
	}
	if err != nil {
		return nil, err
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		// A corrupt state file must not silently skip packages.
		return newCheckpoint(imageID), nil
	}
	if cp.ImageID != imageID || cp.Packages == nil {
		return newCheckpoint(imageID), nil
	}
	return &cp, nil
}

func (c *Checkpoint) save(destDir string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := checkpointPath(destDir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, checkpointPath(destDir))
}
