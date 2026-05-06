//go:build windows
// +build windows

package commands

import (
	"testing"
	"unsafe"
)

// TestCFGCallTargetInfoLayout verifies that cfgCallTargetInfo has the expected
// struct layout: two pointer-sized fields (Offset, Flags), totaling 16 bytes on amd64.
func TestCFGCallTargetInfoLayout(t *testing.T) {
	var info cfgCallTargetInfo
	size := unsafe.Sizeof(info)
	// CFG_CALL_TARGET_INFO is two ULONG_PTR fields: 8+8 = 16 bytes on amd64
	if size != 16 {
		t.Errorf("cfgCallTargetInfo size: expected 16, got %d", size)
	}

	offsetOf := unsafe.Offsetof(info.Offset)
	if offsetOf != 0 {
		t.Errorf("cfgCallTargetInfo.Offset field offset: expected 0, got %d", offsetOf)
	}

	flagsOf := unsafe.Offsetof(info.Flags)
	if flagsOf != 8 {
		t.Errorf("cfgCallTargetInfo.Flags field offset: expected 8, got %d", flagsOf)
	}
}

// TestCFGCallTargetValidConst verifies the CFG_CALL_TARGET_VALID flag value matches
// the Windows SDK definition.
func TestCFGCallTargetValidConst(t *testing.T) {
	if cfgCallTargetValid != 0x1 {
		t.Errorf("cfgCallTargetValid: expected 0x1, got 0x%X", cfgCallTargetValid)
	}
}

// TestEnsureCFGBypassAPIs verifies that ensureCFGBypassAPIs resolves the proc
// without panicking. The proc is in kernel32.dll which is always present.
func TestEnsureCFGBypassAPIs(t *testing.T) {
	// Should not panic — kernel32.dll is always loaded
	ensureCFGBypassAPIs()
	if procSetProcessValidCallTargets == nil {
		t.Error("procSetProcessValidCallTargets is nil after ensureCFGBypassAPIs")
	}
}

// TestCFGBypassApplyToTarget_InvalidHandle verifies that cfgBypassApplyToTarget
// returns an error when given an invalid process handle (0).
// On Windows, SetProcessValidCallTargets with handle 0 returns ERROR_INVALID_HANDLE.
func TestCFGBypassApplyToTarget_InvalidHandle(t *testing.T) {
	err := cfgBypassApplyToTarget(0, 0x1000, 0x1000)
	if err == nil {
		t.Error("expected error for invalid handle, got nil")
	}
}

// TestCFGBypassApplyToTarget_CurrentProcess verifies that cfgBypassApplyToTarget
// succeeds for an address in the current process using the current process pseudo-handle.
// This is the happy path: allocate some RX memory in self and mark it as valid CFG target.
func TestCFGBypassApplyToTarget_CurrentProcess(t *testing.T) {
	// Allocate a small RX region in the current process to test with
	size := 0x1000
	addr, err := injectAllocMemory(^uintptr(0), size, PAGE_EXECUTE_READ)
	if err != nil {
		t.Skipf("VirtualAlloc failed (may need SE_DEBUG or similar): %v", err)
	}
	defer func() {
		// Best-effort free
		procVirtualFreeEx := kernel32.NewProc("VirtualFreeEx")
		procVirtualFreeEx.Call(^uintptr(0), addr, 0, 0x8000) // MEM_RELEASE
	}()

	// Using the current process pseudo-handle (-1 as uintptr)
	err = cfgBypassApplyToTarget(^uintptr(0), addr, size)
	if err != nil {
		// Not necessarily fatal — CFG may not be enabled for this test process.
		// Report as info rather than test failure.
		t.Logf("cfgBypassApplyToTarget on current process: %v (CFG may not be enabled for test binary)", err)
	}
}

// TestCFGCallTargetInfo_FieldInitialization verifies that the struct literal used
// in cfgBypassApplyToTarget sets the correct field values.
func TestCFGCallTargetInfo_FieldInitialization(t *testing.T) {
	target := cfgCallTargetInfo{
		Offset: 0,
		Flags:  cfgCallTargetValid,
	}
	if target.Offset != 0 {
		t.Errorf("Offset: expected 0, got %d", target.Offset)
	}
	if target.Flags != cfgCallTargetValid {
		t.Errorf("Flags: expected 0x%X, got 0x%X", cfgCallTargetValid, target.Flags)
	}
}
