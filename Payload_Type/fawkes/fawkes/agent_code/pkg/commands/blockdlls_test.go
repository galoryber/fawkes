package commands

import (
	"testing"
)

func TestSetBlockDLLsNoOp(t *testing.T) {
	// On non-Windows platforms, SetBlockDLLs is a no-op.
	// This test verifies that calling it with true and false does not panic.
	SetBlockDLLs(true)
	SetBlockDLLs(false)
}
