//go:build !windows
// +build !windows

package commands

// PrepareExecution is a no-op on non-Windows platforms.
// On Windows, this re-applies token impersonation to the current OS thread
// to handle Go's goroutine thread migration.
func PrepareExecution() {}

// CleanupExecution is a no-op on non-Windows platforms.
func CleanupExecution() {}
