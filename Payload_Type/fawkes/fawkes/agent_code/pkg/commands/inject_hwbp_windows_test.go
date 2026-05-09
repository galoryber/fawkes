//go:build windows
// +build windows

package commands

import (
	"strings"
	"testing"
	"unsafe"
)

// On x64, the EXCEPTION_DEBUG_INFO union variant in DEBUG_EVENT must be the
// largest variant so any debug event fits in our struct. Sanity-check the
// known fixed sizes.
func TestEXCEPTION_DEBUG_INFO_Size(t *testing.T) {
	// EXCEPTION_RECORD = 152 (verified via TestEXCEPTION_RECORD_Fields in hwbp_test.go);
	// + dwFirstChance (4) + 4 padding = 160.
	const expected = 160
	if got := unsafe.Sizeof(EXCEPTION_DEBUG_INFO{}); got != expected {
		t.Errorf("EXCEPTION_DEBUG_INFO size = %d, want %d", got, expected)
	}
}

func TestDEBUG_EVENT_HeaderOffsets(t *testing.T) {
	var ev DEBUG_EVENT
	base := uintptr(unsafe.Pointer(&ev))
	if uintptr(unsafe.Pointer(&ev.DwDebugEventCode))-base != 0 {
		t.Errorf("DwDebugEventCode offset = %d, want 0", uintptr(unsafe.Pointer(&ev.DwDebugEventCode))-base)
	}
	if uintptr(unsafe.Pointer(&ev.DwProcessId))-base != 4 {
		t.Errorf("DwProcessId offset = %d, want 4", uintptr(unsafe.Pointer(&ev.DwProcessId))-base)
	}
	if uintptr(unsafe.Pointer(&ev.DwThreadId))-base != 8 {
		t.Errorf("DwThreadId offset = %d, want 8", uintptr(unsafe.Pointer(&ev.DwThreadId))-base)
	}
	// Union (Exception) should start at offset 16 — 12 bytes of header + 4 bytes
	// padding so the EXCEPTION_RECORD inside is 8-byte aligned for its pointer fields.
	if uintptr(unsafe.Pointer(&ev.Exception))-base != 16 {
		t.Errorf("Exception offset = %d, want 16", uintptr(unsafe.Pointer(&ev.Exception))-base)
	}
}

func TestHWBP_DebugConstants(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"EXCEPTION_DEBUG_EVENT_CODE", EXCEPTION_DEBUG_EVENT_CODE, 1},
		{"EXIT_PROCESS_DEBUG_EVENT_CODE", EXIT_PROCESS_DEBUG_EVENT_CODE, 5},
		{"DBG_CONTINUE", DBG_CONTINUE, 0x00010002},
		{"DBG_EXCEPTION_NOT_HANDLED", DBG_EXCEPTION_NOT_HANDLED, 0x80010001},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = 0x%X, want 0x%X", tt.name, tt.got, tt.want)
		}
	}
}

func TestResolveAPIFromTarget_Default(t *testing.T) {
	addr, label, err := resolveAPIFromTarget("")
	if err != nil {
		t.Fatalf("default resolve failed: %v", err)
	}
	if addr == 0 {
		t.Errorf("expected non-zero address for default ntdll!NtDelayExecution")
	}
	if !strings.HasPrefix(label, "ntdll!NtDelayExecution") {
		t.Errorf("label = %q, want prefix ntdll!NtDelayExecution", label)
	}
}

func TestResolveAPIFromTarget_ExplicitNtdll(t *testing.T) {
	addr, label, err := resolveAPIFromTarget("ntdll!NtWaitForSingleObject")
	if err != nil {
		t.Fatalf("explicit resolve failed: %v", err)
	}
	if addr == 0 {
		t.Errorf("expected non-zero address for ntdll!NtWaitForSingleObject")
	}
	if label != "ntdll!NtWaitForSingleObject" {
		t.Errorf("label = %q, want ntdll!NtWaitForSingleObject", label)
	}
}

func TestResolveAPIFromTarget_DllSuffixOptional(t *testing.T) {
	// Both "ntdll" and "ntdll.dll" must resolve to the same address.
	addr1, _, err1 := resolveAPIFromTarget("ntdll!NtDelayExecution")
	addr2, _, err2 := resolveAPIFromTarget("ntdll.dll!NtDelayExecution")
	if err1 != nil || err2 != nil {
		t.Fatalf("ntdll!: err1=%v, ntdll.dll!: err2=%v", err1, err2)
	}
	if addr1 != addr2 {
		t.Errorf("ntdll vs ntdll.dll resolved to different addresses: 0x%X vs 0x%X", addr1, addr2)
	}
}

func TestResolveAPIFromTarget_BadFormat(t *testing.T) {
	cases := []string{"ntdllNtDelayExecution", "!NtDelayExecution", "ntdll!", ""}
	expectErr := []bool{true, true, true, false} // empty defaults to ntdll!NtDelayExecution
	for i, c := range cases {
		_, _, err := resolveAPIFromTarget(c)
		if expectErr[i] && err == nil {
			t.Errorf("case %d (%q): expected error, got nil", i, c)
		}
		if !expectErr[i] && err != nil {
			t.Errorf("case %d (%q): expected success, got %v", i, c, err)
		}
	}
}

func TestResolveAPIFromTarget_UnknownFunction(t *testing.T) {
	_, _, err := resolveAPIFromTarget("ntdll!NtThisFunctionShouldNotExist")
	if err == nil {
		t.Errorf("expected resolution failure for nonexistent function")
	}
}

func TestHwbpInjectShellcode_RejectsCurrentProcess(t *testing.T) {
	currentPID, _, _ := procGetCurrentProcessId.Call()
	_, err := hwbpInjectShellcode(HwbpInjectionParams{
		Shellcode: []byte{0x90, 0x90, 0xc3},
		PID:       uint32(currentPID),
		TargetAPI: "ntdll!NtDelayExecution",
	})
	if err == nil {
		t.Errorf("expected current-process rejection, got nil error")
	}
	if !strings.Contains(err.Error(), "current process") {
		t.Errorf("expected current-process error message, got %q", err.Error())
	}
}

func TestHwbpInjectShellcode_RejectsSystemPID(t *testing.T) {
	for _, pid := range []uint32{0, 4} {
		_, err := hwbpInjectShellcode(HwbpInjectionParams{
			Shellcode: []byte{0x90, 0x90, 0xc3},
			PID:       pid,
		})
		if err == nil {
			t.Errorf("PID %d: expected rejection, got nil error", pid)
		}
	}
}

func TestHwbpInjectShellcode_RejectsEmptyShellcode(t *testing.T) {
	_, err := hwbpInjectShellcode(HwbpInjectionParams{
		Shellcode: nil,
		PID:       9999, // arbitrary, will not be reached
	})
	if err == nil {
		t.Errorf("expected empty-shellcode rejection, got nil error")
	}
	if !strings.Contains(err.Error(), "shellcode is empty") {
		t.Errorf("expected empty-shellcode error message, got %q", err.Error())
	}
}

func TestEnumerateProcessThreads_CurrentProcess(t *testing.T) {
	currentPID, _, _ := procGetCurrentProcessId.Call()
	tids, err := enumerateProcessThreads(uint32(currentPID))
	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}
	if len(tids) == 0 {
		t.Errorf("expected at least one thread for current process, got 0")
	}
}

func TestEnumerateProcessThreads_NonexistentPID(t *testing.T) {
	// PID 0xFFFFFE should not exist; expect zero threads, not an error.
	tids, err := enumerateProcessThreads(0xFFFFFE)
	if err != nil {
		t.Fatalf("enumerate failed: %v", err)
	}
	if len(tids) != 0 {
		t.Errorf("expected 0 threads for nonexistent PID, got %d", len(tids))
	}
}
