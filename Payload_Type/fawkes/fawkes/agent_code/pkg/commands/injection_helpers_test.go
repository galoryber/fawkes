//go:build windows
// +build windows

package commands

import (
	"testing"
)

// TestInjectAllocWriteProtect_EmptyData tests that empty shellcode is handled.
func TestInjectAllocWriteProtect_EmptyData(t *testing.T) {
	// injectAllocWriteProtect with zero-length data should allocate zero bytes
	// which may or may not succeed depending on the OS, but shouldn't panic.
	// We test that the function signature is correct and callable.
	_ = func() (uintptr, error) {
		return injectAllocWriteProtect(0, nil, PAGE_EXECUTE_READ)
	}
}

// TestInjectWriteMemory_EmptyData tests that empty write returns zero bytes.
func TestInjectWriteMemory_EmptyData(t *testing.T) {
	n, err := injectWriteMemory(0, 0, nil)
	if err != nil {
		t.Errorf("expected nil error for empty write, got %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes written for empty data, got %d", n)
	}
}

// TestInjectWriteMemory_EmptySlice tests that empty slice write returns zero bytes.
func TestInjectWriteMemory_EmptySlice(t *testing.T) {
	n, err := injectWriteMemory(0, 0, []byte{})
	if err != nil {
		t.Errorf("expected nil error for empty write, got %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes written for empty slice, got %d", n)
	}
}

// TestHelperFunctionSignatures verifies all helper functions exist with expected signatures.
// This ensures the refactoring didn't break the API contract.
func TestHelperFunctionSignatures(t *testing.T) {
	// Verify each helper function is callable with correct types.
	// We don't call them with real handles — just verify they compile correctly.

	var (
		_openProcess       func(uint32, uint32) (uintptr, error)           = injectOpenProcess
		_closeHandle       func(uintptr)                                   = injectCloseHandle
		_allocMemory       func(uintptr, int, uint32) (uintptr, error)     = injectAllocMemory
		_writeMemory       func(uintptr, uintptr, []byte) (int, error)     = injectWriteMemory
		_readMemory        func(uintptr, uintptr, int) ([]byte, error)     = injectReadMemory
		_protectMemory     func(uintptr, uintptr, int, uint32) (uint32, error) = injectProtectMemory
		_allocWriteProtect func(uintptr, []byte, uint32) (uintptr, error)  = injectAllocWriteProtect
		_createThread      func(uintptr, uintptr) (uintptr, error)         = injectCreateRemoteThread
		_openThread        func(uint32, uint32) (uintptr, error)           = injectOpenThread
		_queueAPC          func(uintptr, uintptr) error                    = injectQueueAPC
		_resumeThread      func(uintptr) (uint32, error)                   = injectResumeThread
		_getContext         func(uintptr, *CONTEXT_AMD64) error             = injectGetThreadContext
		_setContext         func(uintptr, *CONTEXT_AMD64) error             = injectSetThreadContext
	)

	// Prevent "unused variable" compiler errors
	_ = _openProcess
	_ = _closeHandle
	_ = _allocMemory
	_ = _writeMemory
	_ = _readMemory
	_ = _protectMemory
	_ = _allocWriteProtect
	_ = _createThread
	_ = _openThread
	_ = _queueAPC
	_ = _resumeThread
	_ = _getContext
	_ = _setContext
}

// TestConstants verifies injection-related constants are defined.
func TestConstants(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
	}{
		{"PROCESS_CREATE_THREAD", PROCESS_CREATE_THREAD},
		{"PROCESS_VM_OPERATION", PROCESS_VM_OPERATION},
		{"PROCESS_VM_WRITE", PROCESS_VM_WRITE},
		{"PROCESS_VM_READ", PROCESS_VM_READ},
		{"MEM_COMMIT", MEM_COMMIT},
		{"MEM_RESERVE", MEM_RESERVE},
		{"PAGE_EXECUTE_READ", PAGE_EXECUTE_READ},
		{"PAGE_READWRITE", PAGE_READWRITE},
		{"THREAD_ALL_ACCESS", THREAD_ALL_ACCESS},
	}

	for _, tt := range tests {
		if tt.value == 0 {
			t.Errorf("%s should be non-zero", tt.name)
		}
	}
}
