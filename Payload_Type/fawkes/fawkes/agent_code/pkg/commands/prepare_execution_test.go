//go:build !windows
// +build !windows

package commands

import "testing"

func TestPrepareExecution_NoOp(t *testing.T) {
	// PrepareExecution is a no-op on non-Windows — should not panic
	PrepareExecution()
}

func TestCleanupExecution_NoOp(t *testing.T) {
	// CleanupExecution is a no-op on non-Windows — should not panic
	CleanupExecution()
}
