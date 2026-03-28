//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestApcInjection_Name(t *testing.T) {
	cmd := &ApcInjectionCommand{}
	if got := cmd.Name(); got != "apc-injection" {
		t.Errorf("Name() = %q, want %q", got, "apc-injection")
	}
}

func TestApcInjection_ParamParsing(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantShellB64 string
		wantPID      int
		wantTID      int
	}{
		{"full params", `{"shellcode_b64":"AQID","pid":1234,"tid":5678}`, "AQID", 1234, 5678},
		{"minimal", `{"shellcode_b64":"AA==","pid":4,"tid":8}`, "AA==", 4, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params ApcInjectionParams
			if err := json.Unmarshal([]byte(tt.input), &params); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if params.ShellcodeB64 != tt.wantShellB64 {
				t.Errorf("ShellcodeB64 = %q, want %q", params.ShellcodeB64, tt.wantShellB64)
			}
			if params.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", params.PID, tt.wantPID)
			}
			if params.TID != tt.wantTID {
				t.Errorf("TID = %d, want %d", params.TID, tt.wantTID)
			}
		})
	}
}

func TestApcInjection_EmptyShellcode(t *testing.T) {
	cmd := &ApcInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"","pid":1234,"tid":5678}`})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestApcInjection_InvalidPID(t *testing.T) {
	cmd := &ApcInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":0,"tid":5678}`})
	if result.Status != "error" {
		t.Errorf("PID=0 should error, got status=%q", result.Status)
	}
}

func TestApcInjection_InvalidTID(t *testing.T) {
	cmd := &ApcInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":1234,"tid":0}`})
	if result.Status != "error" {
		t.Errorf("TID=0 should error, got status=%q", result.Status)
	}
}

func TestApcInjection_NegativePID(t *testing.T) {
	cmd := &ApcInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: `{"shellcode_b64":"AQID","pid":-1,"tid":5678}`})
	if result.Status != "error" {
		t.Errorf("Negative PID should error, got status=%q", result.Status)
	}
}

func TestApcInjection_InvalidJSON(t *testing.T) {
	cmd := &ApcInjectionCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}
