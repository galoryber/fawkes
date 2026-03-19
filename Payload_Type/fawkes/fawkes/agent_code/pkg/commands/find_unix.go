//go:build linux || darwin
// +build linux darwin

package commands

import (
	"io/fs"
	"syscall"
)

// findFileOwnedBy checks if a file is owned by the specified UID.
func findFileOwnedBy(info fs.FileInfo, uid int64) bool {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int64(stat.Uid) == uid
	}
	return false
}
