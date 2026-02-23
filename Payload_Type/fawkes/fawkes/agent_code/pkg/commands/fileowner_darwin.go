//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
	"time"
)

// getFileOwner returns the owner and group of a file on macOS.
func getFileOwner(path string) (owner, group string) {
	info, err := os.Stat(path)
	if err != nil {
		return "unknown", "unknown"
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown", "unknown"
	}

	if u, err := user.LookupId(fmt.Sprintf("%d", stat.Uid)); err == nil {
		owner = u.Username
	} else {
		owner = fmt.Sprintf("%d", stat.Uid)
	}

	if g, err := user.LookupGroupId(fmt.Sprintf("%d", stat.Gid)); err == nil {
		group = g.Name
	} else {
		group = fmt.Sprintf("%d", stat.Gid)
	}

	return owner, group
}

// getFileTimestamps returns access and creation times on macOS.
func getFileTimestamps(info os.FileInfo) (accessTime, creationTime time.Time) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return info.ModTime(), info.ModTime()
	}
	accessTime = time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
	creationTime = time.Unix(stat.Ctimespec.Sec, stat.Ctimespec.Nsec)
	return accessTime, creationTime
}
