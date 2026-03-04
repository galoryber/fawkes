//go:build !darwin && !windows

package commands

// getfsstatMounts is a no-op on non-darwin platforms.
// Linux uses /proc/mounts (parseProcMounts) instead.
func getfsstatMounts() []mountEntry {
	return nil
}
