//go:build linux && arm64

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestVanillaInjectionArm64_Name(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	if got := cmd.Name(); got != "vanilla-injection" {
		t.Errorf("Name() = %q, want %q", got, "vanilla-injection")
	}
}

func TestVanillaInjectionArm64_Description(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "/proc") {
		t.Errorf("Description should mention /proc, got %q", desc)
	}
}

func TestVanillaInjectionArm64_EmptyShellcode(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"","pid":1234}`})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionArm64_NoShellcode(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid":1234}`})
	if result.Status != "error" {
		t.Errorf("Missing shellcode should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionArm64_InvalidBase64(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"not-base64!!!","pid":1234}`})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionArm64_InvalidPID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":0}`})
	if result.Status != "error" {
		t.Errorf("PID=0 should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionArm64_NegativePID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":-1}`})
	if result.Status != "error" {
		t.Errorf("Negative PID should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionArm64_InvalidJSON(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionArm64_NonexistentPID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":999999999}`})
	if result.Status != "error" {
		t.Errorf("Nonexistent PID should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "not found") && !strings.Contains(result.Output, "PTRACE_ATTACH") {
		t.Errorf("Output should indicate process not found or attach failure, got %q", result.Output)
	}
}

func TestProcMemInjectArm64_InvalidPID(t *testing.T) {
	result := procMemInjectArm64(999999999, []byte{0x1f, 0x20, 0x03, 0xd5})
	if result.Status != "error" {
		t.Errorf("procMemInjectArm64 with invalid PID should error, got status=%q", result.Status)
	}
}
