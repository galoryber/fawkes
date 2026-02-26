//go:build !windows

package main

// initIndirectSyscalls is a no-op on non-Windows platforms.
func initIndirectSyscalls() {}
