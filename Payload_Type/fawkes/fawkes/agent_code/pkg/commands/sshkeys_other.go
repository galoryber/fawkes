//go:build !windows

package commands

// sshKeysEnumerateWindows is a no-op on non-Windows platforms.
func sshKeysEnumerateWindows() string {
	return ""
}
