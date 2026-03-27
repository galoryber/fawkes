//go:build windows

package commands

import (
	"io/fs"
)

// findFileOwnedBy checks if a file is owned by the specified UID.
// On Windows, file ownership uses SIDs rather than UIDs, so this
// always returns true (owner filter is effectively a no-op on Windows).
func findFileOwnedBy(info fs.FileInfo, uid int64) bool {
	_ = info
	return true
}
