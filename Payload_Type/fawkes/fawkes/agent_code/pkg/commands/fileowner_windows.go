//go:build windows

package commands

import (
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// getFileOwner returns the owner and group of a file on Windows using
// GetNamedSecurityInfo + LookupAccountSid.
func getFileOwner(path string) (owner, group string) {
	owner = "unknown"
	group = "unknown"

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
	)
	if err != nil {
		return
	}

	// Get owner SID
	ownerSid, _, err := sd.Owner()
	if err == nil && ownerSid != nil {
		account, domain, _, lookupErr := ownerSid.LookupAccount("")
		if lookupErr == nil {
			if domain != "" {
				owner = domain + "\\" + account
			} else {
				owner = account
			}
		} else {
			owner = ownerSid.String()
		}
	}

	// Get group SID
	groupSid, _, err := sd.Group()
	if err == nil && groupSid != nil {
		account, domain, _, lookupErr := groupSid.LookupAccount("")
		if lookupErr == nil {
			if domain != "" {
				group = domain + "\\" + account
			} else {
				group = account
			}
		} else {
			group = groupSid.String()
		}
	}

	return owner, group
}

// getFileTimestamps returns access and creation times on Windows.
func getFileTimestamps(info os.FileInfo) (accessTime, creationTime time.Time) {
	sys, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return info.ModTime(), info.ModTime()
	}
	accessTime = time.Unix(0, sys.LastAccessTime.Nanoseconds())
	creationTime = time.Unix(0, sys.CreationTime.Nanoseconds())
	return accessTime, creationTime
}
