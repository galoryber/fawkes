//go:build darwin

package commands

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// getPlatformTimestamps returns macOS-specific timestamps (access time)
func getPlatformTimestamps(path string, info os.FileInfo) string {
	stat := info.Sys().(*syscall.Stat_t)
	atime := time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
	return fmt.Sprintf("  Accessed:  %s\n", atime.Format(time.RFC3339))
}

// getAccessTime returns the access time for a file on macOS
func getAccessTime(path string, info os.FileInfo) time.Time {
	stat := info.Sys().(*syscall.Stat_t)
	return time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
}

// copyCreationTime is a no-op on macOS for now (could use birthtime in future)
func copyCreationTime(target, source string) error {
	return nil
}

// setCreationTime is a no-op on macOS for now (could use setattrlist in future)
func setCreationTime(target string, t time.Time) error {
	return nil
}
