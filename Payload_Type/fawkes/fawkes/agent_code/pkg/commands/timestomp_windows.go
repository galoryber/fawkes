//go:build windows
// +build windows

package commands

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// getPlatformTimestamps returns Windows-specific timestamps (access, creation)
func getPlatformTimestamps(path string, info os.FileInfo) string {
	sys := info.Sys().(*syscall.Win32FileAttributeData)
	output := ""
	output += fmt.Sprintf("  Accessed:  %s\n", time.Unix(0, sys.LastAccessTime.Nanoseconds()).Format(time.RFC3339))
	output += fmt.Sprintf("  Created:   %s\n", time.Unix(0, sys.CreationTime.Nanoseconds()).Format(time.RFC3339))
	return output
}

// getAccessTime returns the access time for a file on Windows
func getAccessTime(path string, info os.FileInfo) time.Time {
	sys := info.Sys().(*syscall.Win32FileAttributeData)
	return time.Unix(0, sys.LastAccessTime.Nanoseconds())
}

// copyCreationTime copies the creation time from source to target on Windows
func copyCreationTime(target, source string) error {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return err
	}
	sys := sourceInfo.Sys().(*syscall.Win32FileAttributeData)
	creationTime := time.Unix(0, sys.CreationTime.Nanoseconds())
	return setCreationTime(target, creationTime)
}

// setCreationTime sets the creation time on Windows using SetFileTime
func setCreationTime(target string, t time.Time) error {
	pathp, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}

	h, err := syscall.CreateFile(pathp,
		syscall.FILE_WRITE_ATTRIBUTES,
		syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS, // needed for directories
		0)
	if err != nil {
		return fmt.Errorf("CreateFile: %v", err)
	}
	defer syscall.CloseHandle(h)

	ft := syscall.NsecToFiletime(t.UnixNano())
	return syscall.SetFileTime(h, &ft, nil, nil)
}
