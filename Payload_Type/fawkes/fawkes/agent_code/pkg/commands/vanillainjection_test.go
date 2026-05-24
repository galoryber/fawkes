//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestVanillaInjection_Name(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	if got := cmd.Name(); got != "vanilla-injection" {
		t.Errorf("Name() = %q, want %q", got, "vanilla-injection")
	}
}

func TestVanillaInjection_ParamParsing(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantShellB64 string
		wantPID      int
	}{
		{"normal", `{"shellcode_b64":"AQID","pid":1234}`, "AQID", 1234},
		{"high PID", `{"shellcode_b64":"BAUG","pid":65535}`, "BAUG", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params VanillaInjectionParams
			if err := json.Unmarshal([]byte(tt.input), &params); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if params.ShellcodeB64 != tt.wantShellB64 {
				t.Errorf("ShellcodeB64 = %q, want %q", params.ShellcodeB64, tt.wantShellB64)
			}
			if params.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", params.PID, tt.wantPID)
			}
		})
	}
}

func TestVanillaInjection_EmptyShellcode(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"","pid":1234}`})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestVanillaInjection_InvalidPID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":0}`})
	if result.Status != "error" {
		t.Errorf("PID=0 should error, got status=%q", result.Status)
	}
}

func TestVanillaInjection_NegativePID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":-1}`})
	if result.Status != "error" {
		t.Errorf("Negative PID should error, got status=%q", result.Status)
	}
}

func TestVanillaInjection_InvalidJSON(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestVanillaInjection_MigrateEmptyShellcode(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"","pid":1234,"action":"migrate"}`})
	if result.Status != "error" {
		t.Errorf("Migrate with empty shellcode should error, got status=%q", result.Status)
	}
}

func TestVanillaInjection_MigrateInvalidPID(t *testing.T) {
	cmd := &VanillaInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":0,"action":"migrate"}`})
	if result.Status != "error" {
		t.Errorf("Migrate with PID=0 should error, got status=%q", result.Status)
	}
}
