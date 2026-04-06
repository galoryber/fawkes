//go:build !windows

package commands

// getRunningProcessNamesWindows is a no-op on non-Windows platforms.
// Process enumeration is handled in securityinfo_edr.go via /proc or ps.
func getRunningProcessNamesWindows() map[string]int {
	return make(map[string]int)
}
