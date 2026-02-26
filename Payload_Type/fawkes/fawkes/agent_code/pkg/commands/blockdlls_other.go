//go:build !windows

package commands

func blockDLLsSet(_ bool) {}

// SetDefaultPPID is a no-op on non-Windows platforms.
func SetDefaultPPID(_ int) {}

// GetDefaultPPID always returns 0 on non-Windows platforms.
func GetDefaultPPID() int { return 0 }
