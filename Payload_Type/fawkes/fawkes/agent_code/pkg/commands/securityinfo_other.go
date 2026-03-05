//go:build !windows

package commands

// securityInfoWindowsNative is a no-op stub on non-Windows platforms.
func securityInfoWindowsNative() []secControl { return nil }
