//go:build !windows

package commands

// pkgListWindowsNative is a no-op stub on non-Windows platforms.
func pkgListWindowsNative(filter string) string { return "" }
