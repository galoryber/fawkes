//go:build linux && amd64

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPtraceInjectName(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	if cmd.Name() != "ptrace-inject" {
		t.Errorf("expected 'ptrace-inject', got '%s'", cmd.Name())
	}
}

func TestPtraceInjectDescription(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	if !strings.Contains(cmd.Description(), "ptrace") {
		t.Errorf("description should mention ptrace: %s", cmd.Description())
	}
}

func TestPtraceInjectEmptyParams(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %s", result.Status)
	}
}

func TestPtraceInjectBadJSON(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %s", result.Status)
	}
}

func TestPtraceInjectInvalidAction(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got: %s", result.Output)
	}
}

func TestPtraceInjectCheck(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "check"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for check, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Ptrace Configuration") {
		t.Errorf("check output should contain 'Ptrace Configuration': %s", result.Output)
	}
	if !strings.Contains(result.Output, "UID") {
		t.Errorf("check output should contain UID info: %s", result.Output)
	}
}

func TestPtraceInjectMissingPID(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"action":        "inject",
		"shellcode_b64": base64.StdEncoding.EncodeToString([]byte{0xCC}),
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "pid required") {
		t.Errorf("expected pid error, got: %s", result.Output)
	}
}

func TestPtraceInjectMissingShellcode(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"action": "inject",
		"pid":    9999,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "shellcode_b64 required") {
		t.Errorf("expected shellcode error, got: %s", result.Output)
	}
}

func TestPtraceInjectEmptyShellcode(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	// Empty base64 encoding produces "" which hits the "required" check
	params, _ := json.Marshal(map[string]interface{}{
		"action":        "inject",
		"pid":           9999,
		"shellcode_b64": "",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "shellcode_b64 required") {
		t.Errorf("expected shellcode required error, got: %s", result.Output)
	}
}

func TestPtraceInjectBadBase64(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"action":        "inject",
		"pid":           9999,
		"shellcode_b64": "not-valid-base64!@#$",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "decoding") {
		t.Errorf("expected decode error, got: %s", result.Output)
	}
}

func TestPtraceInjectNonexistentProcess(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	// Use a PID that almost certainly doesn't exist
	params, _ := json.Marshal(map[string]interface{}{
		"action":        "inject",
		"pid":           999999,
		"shellcode_b64": base64.StdEncoding.EncodeToString([]byte{0x90, 0xCC}),
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent process, got %s: %s", result.Status, result.Output)
	}
}

func TestPtraceInjectDefaultAction(t *testing.T) {
	// When action is empty, default should be "inject"
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"pid":           999999,
		"shellcode_b64": base64.StdEncoding.EncodeToString([]byte{0x90, 0xCC}),
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should try inject and fail on nonexistent process
	if result.Status != "error" || !strings.Contains(result.Output, "not found") {
		t.Errorf("expected not found error for default inject action, got: %s", result.Output)
	}
}

func TestFindSyscallGadget(t *testing.T) {
	// Find syscall gadget in our own process
	pid := os.Getpid()
	addr, err := findSyscallGadget(pid)
	if err != nil {
		t.Fatalf("failed to find syscall gadget in self: %v", err)
	}
	if addr == 0 {
		t.Fatal("expected non-zero syscall gadget address")
	}
	t.Logf("Found syscall gadget at 0x%X", addr)
}

func TestFindSyscallGadgetNonexistent(t *testing.T) {
	_, err := findSyscallGadget(999999)
	if err == nil {
		t.Fatal("expected error for nonexistent process")
	}
	if !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("expected 'cannot read' error, got: %v", err)
	}
}

func TestPtraceCheckShowsCapabilities(t *testing.T) {
	result := ptraceCheck()
	if result.Status != "success" {
		t.Fatalf("ptraceCheck failed: %s", result.Output)
	}
	// Should show capabilities
	if !strings.Contains(result.Output, "Cap") {
		t.Errorf("check output should contain capability info")
	}
	// Should show current UID
	if !strings.Contains(result.Output, fmt.Sprintf("Current UID:  %d", os.Getuid())) {
		t.Errorf("check output should contain current UID")
	}
}
