//go:build !windows
// +build !windows

package main

// tryRunAsService is a no-op on non-Windows platforms.
// Only Windows has the Service Control Manager.
func tryRunAsService() bool {
	return false
}
