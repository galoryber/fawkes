//go:build !windows

package main

// autoStartupPatch is a no-op on non-Windows platforms.
// ETW and AMSI are Windows-specific technologies.
func autoStartupPatch() {}
