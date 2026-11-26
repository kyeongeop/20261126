//go:build linux

package guest

import (
	"os"
	"syscall"
)

func fileIdentity(info os.FileInfo) (dev, ino uint64, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return stat.Dev, stat.Ino, true
}
