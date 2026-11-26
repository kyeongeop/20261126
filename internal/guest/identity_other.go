//go:build !linux

package guest

import "os"

func fileIdentity(info os.FileInfo) (dev, ino uint64, ok bool) {
	return 0, 0, false
}
