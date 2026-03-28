//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestAutoPatch_Name(t *testing.T) {
	cmd := &AutoPatchCommand{}
	if got := cmd.Name(); got != "autopatch" {
		t.Errorf("Name() = %q, want %q", got, "autopatch")
	}
}

func TestAutoPatch_JSONParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantDll  string
		wantFunc string
		wantN    int
	}{
		{"full params", `{"dll_name":"amsi.dll","function_name":"AmsiScanBuffer","num_bytes":64}`, "amsi.dll", "AmsiScanBuffer", 64},
		{"ntdll", `{"dll_name":"ntdll.dll","function_name":"EtwEventWrite","num_bytes":32}`, "ntdll.dll", "EtwEventWrite", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args AutoPatchArgs
			if err := json.Unmarshal([]byte(tt.input), &args); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if args.DllName != tt.wantDll {
				t.Errorf("DllName = %q, want %q", args.DllName, tt.wantDll)
			}
			if args.FunctionName != tt.wantFunc {
				t.Errorf("FunctionName = %q, want %q", args.FunctionName, tt.wantFunc)
			}
			if args.NumBytes != tt.wantN {
				t.Errorf("NumBytes = %d, want %d", args.NumBytes, tt.wantN)
			}
		})
	}
}

func TestAutoPatch_SpaceSeparatedParsing(t *testing.T) {
	cmd := &AutoPatchCommand{}

	// Valid space-separated input
	result := cmd.Execute(structs.Task{Params: "amsi.dll AmsiScanBuffer 64"})
	// This will fail because we can't actually load amsi.dll in tests,
	// but it should NOT fail on parsing
	if result.Status == "error" && result.Output == "Error: Invalid arguments. Usage: autopatch <dll_name> <function_name> <num_bytes>" {
		t.Error("Space-separated parsing failed — should accept 3 fields")
	}
}

func TestAutoPatch_InvalidParams(t *testing.T) {
	cmd := &AutoPatchCommand{}

	tests := []struct {
		name   string
		params string
	}{
		{"too few fields", "amsi.dll AmsiScanBuffer"},
		{"single field", "amsi.dll"},
		{"non-numeric bytes", "amsi.dll AmsiScanBuffer abc"},
		{"zero bytes", "amsi.dll AmsiScanBuffer 0"},
		{"negative bytes", "amsi.dll AmsiScanBuffer -1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cmd.Execute(structs.Task{Params: tt.params})
			if result.Status != "error" {
				t.Errorf("Expected error for %q, got status=%q output=%q", tt.params, result.Status, result.Output)
			}
		})
	}
}
