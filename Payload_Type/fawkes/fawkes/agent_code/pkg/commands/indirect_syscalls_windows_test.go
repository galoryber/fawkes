//go:build windows
// +build windows

package commands

import (
	"testing"
	"unsafe"
)

// TestSyscallEntryFields verifies SyscallEntry struct field layout.
func TestSyscallEntryFields(t *testing.T) {
	entry := SyscallEntry{
		Name:       "NtAllocateVirtualMemory",
		Number:     0x18,
		FuncAddr:   0x00007FFD12340000,
		SyscallRet: 0x00007FFD12340012,
		StubAddr:   0x00000001F0000000,
	}

	if entry.Name != "NtAllocateVirtualMemory" {
		t.Errorf("Name: got %q", entry.Name)
	}
	if entry.Number != 0x18 {
		t.Errorf("Number: expected 0x18, got 0x%X", entry.Number)
	}
	if entry.FuncAddr == 0 {
		t.Error("FuncAddr should be non-zero")
	}
	if entry.SyscallRet == 0 {
		t.Error("SyscallRet should be non-zero")
	}
	if entry.StubAddr == 0 {
		t.Error("StubAddr should be non-zero")
	}
}

// TestSyscallResolverInitialState verifies resolver starts uninitialized.
func TestSyscallResolverInitialState(t *testing.T) {
	var r SyscallResolver
	if r.initialized {
		t.Error("new resolver should not be initialized")
	}
	if r.entries != nil {
		t.Error("entries should be nil initially")
	}
	if r.stubPool != 0 {
		t.Error("stubPool should be 0 initially")
	}
}

// TestImageExportDirectorySize verifies the PE export directory struct size.
func TestImageExportDirectorySize(t *testing.T) {
	// IMAGE_EXPORT_DIRECTORY: 4+4+2+2+4+4+4+4+4+4+4 = 40 bytes
	size := unsafe.Sizeof(imageExportDirectory{})
	if size != 40 {
		t.Errorf("imageExportDirectory size: expected 40, got %d", size)
	}
}

// TestIndirectSyscallsAvailable verifies the availability check.
func TestIndirectSyscallsAvailable(t *testing.T) {
	// IndirectSyscallsAvailable should return a bool based on the global flag
	result := IndirectSyscallsAvailable()
	// On a test system, syscalls may or may not be initialized
	_ = result // Just verify it doesn't panic
}

// TestGetResolvedSyscalls verifies the getter function.
func TestGetResolvedSyscalls(t *testing.T) {
	resolved := GetResolvedSyscalls()
	if !IndirectSyscallsAvailable() && resolved != nil {
		// If not initialized, should return nil or empty map
		t.Log("Syscalls not initialized, got non-nil map — may be from previous init")
	}
}

// TestCStringToGo verifies C string conversion.
func TestCStringToGo(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		maxLen   int
		expected string
	}{
		{
			name:     "simple string",
			input:    []byte{'H', 'e', 'l', 'l', 'o', 0, 'X'},
			maxLen:   10,
			expected: "Hello",
		},
		{
			name:     "maxLen truncation",
			input:    []byte{'A', 'B', 'C', 'D', 'E'},
			maxLen:   3,
			expected: "ABC",
		},
		{
			name:     "empty string (null at start)",
			input:    []byte{0, 'A', 'B'},
			maxLen:   10,
			expected: "",
		},
		{
			name:     "single character",
			input:    []byte{'Z', 0},
			maxLen:   10,
			expected: "Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cStringToGo(&tt.input[0], tt.maxLen)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCStringToGo_Nil(t *testing.T) {
	result := cStringToGo(nil, 100)
	if result != "" {
		t.Errorf("nil pointer should return empty string, got %q", result)
	}
}

// TestSyscallFunctionSignatures verifies all Indirect* functions exist
// and have the expected parameter types.
func TestSyscallFunctionSignatures(t *testing.T) {
	var (
		_alloc      func(uintptr, *uintptr, *uintptr, uint32, uint32) uint32 = IndirectNtAllocateVirtualMemory
		_write      func(uintptr, uintptr, uintptr, uintptr, *uintptr) uint32 = IndirectNtWriteVirtualMemory
		_protect    func(uintptr, *uintptr, *uintptr, uint32, *uint32) uint32 = IndirectNtProtectVirtualMemory
		_createTh   func(*uintptr, uintptr, uintptr) uint32                   = IndirectNtCreateThreadEx
		_createThA  func(*uintptr, uintptr, uintptr, uintptr) uint32          = IndirectNtCreateThreadExWithArg
		_free       func(uintptr, *uintptr, *uintptr, uint32) uint32          = IndirectNtFreeVirtualMemory
		_openProc   func(*uintptr, uint32, uintptr) uint32                    = IndirectNtOpenProcess
		_resume     func(uintptr, *uint32) uint32                             = IndirectNtResumeThread
		_getCtx     func(uintptr, uintptr) uint32                             = IndirectNtGetContextThread
		_setCtx     func(uintptr, uintptr) uint32                             = IndirectNtSetContextThread
		_openThread func(*uintptr, uint32, uintptr) uint32                    = IndirectNtOpenThread
		_queueApc   func(uintptr, uintptr, uintptr, uintptr, uintptr) uint32 = IndirectNtQueueApcThread
		_read       func(uintptr, uintptr, uintptr, uintptr, *uintptr) uint32 = IndirectNtReadVirtualMemory
		_close      func(uintptr) uint32                                      = IndirectNtClose
	)

	_ = _alloc
	_ = _write
	_ = _protect
	_ = _createTh
	_ = _createThA
	_ = _free
	_ = _openProc
	_ = _resume
	_ = _getCtx
	_ = _setCtx
	_ = _openThread
	_ = _queueApc
	_ = _read
	_ = _close
}

// TestTargetSyscallNames lists the Nt* functions that should be resolved.
func TestTargetSyscallNames(t *testing.T) {
	expectedNames := []string{
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"NtFreeVirtualMemory",
		"NtOpenProcess",
		"NtResumeThread",
		"NtGetContextThread",
		"NtSetContextThread",
		"NtOpenThread",
		"NtQueueApcThread",
		"NtReadVirtualMemory",
		"NtClose",
	}

	if IndirectSyscallsAvailable() {
		resolved := GetResolvedSyscalls()
		for _, name := range expectedNames {
			entry, ok := resolved[name]
			if !ok {
				t.Errorf("expected %q to be resolved", name)
				continue
			}
			if entry.Number == 0 && entry.FuncAddr == 0 {
				t.Errorf("%q has zero syscall number and address", name)
			}
		}
	} else {
		t.Skip("indirect syscalls not initialized, skipping resolution check")
	}
}
