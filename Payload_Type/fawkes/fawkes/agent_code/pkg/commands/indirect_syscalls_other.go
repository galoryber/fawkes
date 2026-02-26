//go:build !windows

package commands

// InitIndirectSyscalls is a no-op on non-Windows platforms
func InitIndirectSyscalls() error { return nil }

// IndirectSyscallsAvailable always returns false on non-Windows
func IndirectSyscallsAvailable() bool { return false }
