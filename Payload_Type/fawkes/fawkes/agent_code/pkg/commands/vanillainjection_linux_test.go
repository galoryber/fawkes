//go:build linux && amd64

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestVanillaInjectionLinux_Name(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	if got := cmd.Name(); got != "vanilla-injection" {
		t.Errorf("Name() = %q, want %q", got, "vanilla-injection")
	}
}

func TestVanillaInjectionLinux_Description(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "/proc") {
		t.Errorf("Description should mention /proc, got %q", desc)
	}
}

func TestVanillaInjectionLinux_EmptyShellcode(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"","pid":1234}`})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionLinux_NoShellcode(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid":1234}`})
	if result.Status != "error" {
		t.Errorf("Missing shellcode should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionLinux_InvalidBase64(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"not-base64!!!","pid":1234}`})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionLinux_InvalidPID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":0}`})
	if result.Status != "error" {
		t.Errorf("PID=0 should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionLinux_NegativePID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":-1}`})
	if result.Status != "error" {
		t.Errorf("Negative PID should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionLinux_InvalidJSON(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestVanillaInjectionLinux_NonexistentPID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":999999999}`})
	if result.Status != "error" {
		t.Errorf("Nonexistent PID should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "not found") && !strings.Contains(result.Output, "PTRACE_ATTACH") {
		t.Errorf("Output should indicate process not found or attach failure, got %q", result.Output)
	}
}

func TestVanillaInjectionLinux_MigrateEmptyShellcode(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"","pid":1234,"action":"migrate"}`})
	if result.Status != "error" {
		t.Errorf("Migrate with empty shellcode should error, got status=%q", result.Status)
	}
}

func TestProcMemInject_InvalidPID(t *testing.T) {
	result := procMemInject(999999999, []byte{0x90, 0xC3})
	if result.Status != "error" {
		t.Errorf("procMemInject with invalid PID should error, got status=%q", result.Status)
	}
}
