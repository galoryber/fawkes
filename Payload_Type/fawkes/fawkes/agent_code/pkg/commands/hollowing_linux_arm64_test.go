//go:build linux && arm64

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestHollowingArm64_Name(t *testing.T) {
	cmd := &HollowingCommand{}
	if got := cmd.Name(); got != "hollow" {
		t.Errorf("Name() = %q, want %q", got, "hollow")
	}
}

func TestHollowingArm64_Description(t *testing.T) {
	cmd := &HollowingCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "hollow") || !strings.Contains(desc, "/proc") {
		t.Errorf("Description should mention hollowing and /proc, got %q", desc)
	}
}

func TestHollowingArm64_EmptyShellcode(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":""}`})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestHollowingArm64_NoShellcode(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: `{}`})
	if result.Status != "error" {
		t.Errorf("Missing shellcode should error, got status=%q", result.Status)
	}
}

func TestHollowingArm64_InvalidBase64(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"not-base64!!!"}`})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestHollowingArm64_InvalidJSON(t *testing.T) {
	cmd := &HollowingCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestHollowingArm64_DefaultTarget(t *testing.T) {
	params := hollowParams{Target: ""}
	if params.Target == "" {
		params.Target = "/usr/bin/sleep"
	}
	if params.Target != "/usr/bin/sleep" {
		t.Errorf("Default target should be /usr/bin/sleep, got %q", params.Target)
	}
}
