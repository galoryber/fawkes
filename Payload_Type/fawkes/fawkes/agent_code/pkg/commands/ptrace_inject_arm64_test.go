//go:build linux && arm64

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

func TestPtraceInjectArm64Name(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	if cmd.Name() != "ptrace-inject" {
		t.Errorf("expected 'ptrace-inject', got '%s'", cmd.Name())
	}
}

func TestPtraceInjectArm64Description(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	if !strings.Contains(cmd.Description(), "ptrace") {
		t.Errorf("description should mention ptrace: %s", cmd.Description())
	}
}

func TestPtraceInjectArm64EmptyParams(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %s", result.Status)
	}
}

func TestPtraceInjectArm64BadJSON(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %s", result.Status)
	}
}

func TestPtraceInjectArm64InvalidAction(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got: %s", result.Output)
	}
}

func TestPtraceInjectArm64Check(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "check"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for check, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Ptrace Configuration") {
		t.Errorf("check output should contain 'Ptrace Configuration': %s", result.Output)
	}
}

func TestPtraceInjectArm64MissingPID(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"action":        "inject",
		"shellcode_b64": base64.StdEncoding.EncodeToString([]byte{0x00, 0x00, 0x20, 0xD4}),
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "pid required") {
		t.Errorf("expected pid error, got: %s", result.Output)
	}
}

func TestPtraceInjectArm64MissingShellcode(t *testing.T) {
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

func TestPtraceInjectArm64BadBase64(t *testing.T) {
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

func TestPtraceInjectArm64NonexistentProcess(t *testing.T) {
	cmd := &PtraceInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"action":        "inject",
		"pid":           999999,
		"shellcode_b64": base64.StdEncoding.EncodeToString([]byte{0x1f, 0x20, 0x03, 0xd5}),
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent process, got %s: %s", result.Status, result.Output)
	}
}

func TestFindSvcGadgetArm64(t *testing.T) {
	pid := os.Getpid()
	addr, err := findSyscallGadget(pid)
	if err != nil {
		t.Fatalf("failed to find SVC gadget in self: %v", err)
	}
	if addr == 0 {
		t.Fatal("expected non-zero SVC gadget address")
	}
	if addr%4 != 0 {
		t.Errorf("SVC gadget address 0x%X is not 4-byte aligned", addr)
	}
	t.Logf("Found SVC gadget at 0x%X", addr)
}

func TestFindSvcGadgetArm64Nonexistent(t *testing.T) {
	_, err := findSyscallGadget(999999)
	if err == nil {
		t.Fatal("expected error for nonexistent process")
	}
	if !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("expected 'cannot read' error, got: %v", err)
	}
}

func TestPtraceCheckArm64ShowsCapabilities(t *testing.T) {
	result := ptraceCheck()
	if result.Status != "success" {
		t.Fatalf("ptraceCheck failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Cap") {
		t.Errorf("check output should contain capability info")
	}
	if !strings.Contains(result.Output, fmt.Sprintf("Current UID:  %d", os.Getuid())) {
		t.Errorf("check output should contain current UID")
	}
}
