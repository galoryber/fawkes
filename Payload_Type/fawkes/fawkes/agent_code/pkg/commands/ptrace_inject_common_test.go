//go:build linux

package commands

import (
	"encoding/base64"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestPtraceValidateAndDecode_ValidArgs(t *testing.T) {
	sc := []byte{0x90, 0x90, 0xCC}
	b64 := base64.StdEncoding.EncodeToString(sc)
	shellcode, restore, timeout, err := ptraceValidateAndDecode(ptraceInjectArgs{
		PID:          1234,
		ShellcodeB64: b64,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(shellcode) != 3 || shellcode[2] != 0xCC {
		t.Errorf("shellcode mismatch: got %x", shellcode)
	}
	if !restore {
		t.Error("restore should default to true")
	}
	if timeout != 30 {
		t.Errorf("timeout should default to 30, got %d", timeout)
	}
}

func TestPtraceValidateAndDecode_InvalidPID(t *testing.T) {
	for _, pid := range []int{0, -1, -999} {
		_, _, _, err := ptraceValidateAndDecode(ptraceInjectArgs{PID: pid, ShellcodeB64: "AAAA"})
		if err == nil {
			t.Errorf("expected error for pid=%d", pid)
		}
		if !strings.Contains(err.Error(), "valid pid") {
			t.Errorf("expected 'valid pid' in error, got: %v", err)
		}
	}
}

func TestPtraceValidateAndDecode_EmptyShellcode(t *testing.T) {
	_, _, _, err := ptraceValidateAndDecode(ptraceInjectArgs{PID: 1, ShellcodeB64: ""})
	if err == nil || !strings.Contains(err.Error(), "shellcode_b64 required") {
		t.Errorf("expected 'shellcode_b64 required' error, got: %v", err)
	}
}

func TestPtraceValidateAndDecode_BadBase64(t *testing.T) {
	_, _, _, err := ptraceValidateAndDecode(ptraceInjectArgs{PID: 1, ShellcodeB64: "!!!not-base64!!!"})
	if err == nil || !strings.Contains(err.Error(), "decoding shellcode") {
		t.Errorf("expected 'decoding shellcode' error, got: %v", err)
	}
}

func TestPtraceValidateAndDecode_EmptyDecodedShellcode(t *testing.T) {
	_, _, _, err := ptraceValidateAndDecode(ptraceInjectArgs{PID: 1, ShellcodeB64: ""})
	if err == nil {
		t.Error("expected error for empty shellcode_b64")
	}
}

func TestPtraceValidateAndDecode_RestoreOverride(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte{0x90})
	f := false
	_, restore, _, err := ptraceValidateAndDecode(ptraceInjectArgs{
		PID: 1, ShellcodeB64: b64, Restore: &f,
	})
	if err != nil {
		t.Fatal(err)
	}
	if restore {
		t.Error("restore should be false when explicitly set")
	}
}

func TestPtraceValidateAndDecode_TimeoutOverride(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte{0x90})
	_, _, timeout, err := ptraceValidateAndDecode(ptraceInjectArgs{
		PID: 1, ShellcodeB64: b64, Timeout: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if timeout != 60 {
		t.Errorf("timeout should be 60, got %d", timeout)
	}
}

func TestPtraceValidateAndDecode_NegativeTimeout(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte{0x90})
	_, _, timeout, err := ptraceValidateAndDecode(ptraceInjectArgs{
		PID: 1, ShellcodeB64: b64, Timeout: -5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if timeout != 30 {
		t.Errorf("negative timeout should default to 30, got %d", timeout)
	}
}

func TestPtraceCheckProcess_Self(t *testing.T) {
	if err := ptraceCheckProcess(1); err != nil {
		t.Errorf("PID 1 should exist: %v", err)
	}
}

func TestPtraceCheckProcess_Nonexistent(t *testing.T) {
	err := ptraceCheckProcess(999999999)
	if err == nil {
		t.Error("expected error for nonexistent PID")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestPtraceReportCompletion_Timeout(t *testing.T) {
	var sb strings.Builder
	result := ptraceReportCompletion(false, 0, 30, &sb)
	if result {
		t.Error("should return false on timeout")
	}
	out := sb.String()
	if !strings.Contains(out, "Timeout after 30s") {
		t.Errorf("expected timeout message, got: %s", out)
	}
	if !strings.Contains(out, "Detaching without restore") {
		t.Errorf("expected detach message, got: %s", out)
	}
}

func TestPtraceReportCompletion_SIGTRAP(t *testing.T) {
	var sb strings.Builder
	ws := syscall.WaitStatus(int(syscall.SIGTRAP)<<8 | 0x7f)
	result := ptraceReportCompletion(true, ws, 30, &sb)
	if !result {
		t.Error("should return true on SIGTRAP")
	}
	if !strings.Contains(sb.String(), "Shellcode completed") {
		t.Errorf("expected SIGTRAP message, got: %s", sb.String())
	}
}

func TestPtraceReportCompletion_OtherSignal(t *testing.T) {
	var sb strings.Builder
	ws := syscall.WaitStatus(int(syscall.SIGSEGV)<<8 | 0x7f)
	result := ptraceReportCompletion(true, ws, 30, &sb)
	if !result {
		t.Error("should return true (process stopped)")
	}
	if !strings.Contains(sb.String(), fmt.Sprintf("signal %d", syscall.SIGSEGV)) {
		t.Errorf("expected signal number in message, got: %s", sb.String())
	}
}

func TestPtraceMprotectCheck_Success(t *testing.T) {
	var sb strings.Builder
	ptraceMprotectCheck(0, &sb)
	if !strings.Contains(sb.String(), "read+execute") {
		t.Errorf("expected success message, got: %s", sb.String())
	}
}

func TestPtraceMprotectCheck_NonZero(t *testing.T) {
	var sb strings.Builder
	ptraceMprotectCheck(22, &sb)
	out := sb.String()
	if !strings.Contains(out, "non-zero") {
		t.Errorf("expected non-zero warning, got: %s", out)
	}
	if !strings.Contains(out, "22") {
		t.Errorf("expected return value in message, got: %s", out)
	}
}
