//go:build !windows
// +build !windows

package commands

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// getPlatformTimestamps returns Unix-specific timestamps (access time)
func getPlatformTimestamps(path string, info os.FileInfo) string {
	stat := info.Sys().(*syscall.Stat_t)
	atime := time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
	return fmt.Sprintf("  Accessed:  %s\n", atime.Format(time.RFC3339))
}

// getAccessTime returns the access time for a file on Unix
func getAccessTime(path string, info os.FileInfo) time.Time {
	stat := info.Sys().(*syscall.Stat_t)
	return time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
}

// copyCreationTime is a no-op on Unix (no creation time concept in standard filesystems)
func copyCreationTime(target, source string) error {
	return nil
}

// setCreationTime is a no-op on Unix (no creation time concept in standard filesystems)
func setCreationTime(target string, t time.Time) error {
	return nil
}
