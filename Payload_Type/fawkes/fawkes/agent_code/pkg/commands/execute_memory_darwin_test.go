//go:build darwin

package commands

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestExecuteMemoryCommand_Name(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	if cmd.Name() != "execute-memory" {
		t.Errorf("expected 'execute-memory', got %q", cmd.Name())
	}
}

func TestExecuteMemoryCommand_Description(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "Mach-O") {
		t.Errorf("expected description to mention Mach-O, got: %s", desc)
	}
	if !strings.Contains(desc, "T1620") {
		t.Errorf("expected description to reference T1620, got: %s", desc)
	}
}

func TestExecuteMemoryCommand_EmptyParams(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
	if !strings.Contains(result.Output, "binary_b64 parameter required") {
		t.Errorf("expected helpful error message, got: %s", result.Output)
	}
}

func TestExecuteMemoryCommand_InvalidJSON(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestExecuteMemoryCommand_EmptyBinary(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for empty binary")
	}
	if !strings.Contains(result.Output, "binary_b64 is empty") {
		t.Errorf("expected empty binary error, got: %s", result.Output)
	}
}

func TestExecuteMemoryCommand_InvalidBase64(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: "not-valid-base64!!!"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for invalid base64")
	}
	if !strings.Contains(result.Output, "decoding binary") {
		t.Errorf("expected decode error, got: %s", result.Output)
	}
}

func TestExecuteMemoryCommand_TooSmall(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	// 3 bytes - too small to be valid
	smallData := base64.StdEncoding.EncodeToString([]byte{0xCF, 0xFA, 0xED})
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: smallData})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for too-small binary")
	}
	if !strings.Contains(result.Output, "too small") {
		t.Errorf("expected too-small error, got: %s", result.Output)
	}
}

func TestExecuteMemoryCommand_NotMachO(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	// PE magic (not Mach-O)
	notMachO := base64.StdEncoding.EncodeToString([]byte{0x4D, 0x5A, 0x90, 0x00, 0x03})
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: notMachO})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for non-Mach-O binary")
	}
	if !strings.Contains(result.Output, "not a valid Mach-O") {
		t.Errorf("expected Mach-O validation error, got: %s", result.Output)
	}
}

func TestExecuteMemoryCommand_NotELF(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	// ELF magic - should be rejected on macOS
	elfData := base64.StdEncoding.EncodeToString([]byte{0x7F, 0x45, 0x4C, 0x46, 0x02})
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: elfData})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for ELF binary on macOS")
	}
}

func TestIsValidMachO(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"MH_MAGIC_64 (64-bit LE)", []byte{0xCF, 0xFA, 0xED, 0xFE}, true},
		{"MH_MAGIC (32-bit LE)", []byte{0xCE, 0xFA, 0xED, 0xFE}, true},
		{"MH_CIGAM_64 (64-bit BE)", []byte{0xFE, 0xED, 0xFA, 0xCF}, true},
		{"MH_CIGAM (32-bit BE)", []byte{0xFE, 0xED, 0xFA, 0xCE}, true},
		{"FAT_MAGIC (universal)", []byte{0xCA, 0xFE, 0xBA, 0xBE}, true},
		{"FAT_CIGAM (universal reversed)", []byte{0xBE, 0xBA, 0xFE, 0xCA}, true},
		{"ELF magic", []byte{0x7F, 0x45, 0x4C, 0x46}, false},
		{"PE magic", []byte{0x4D, 0x5A, 0x90, 0x00}, false},
		{"empty", []byte{}, false},
		{"too short", []byte{0xCF, 0xFA, 0xED}, false},
		{"zeros", []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"random bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidMachO(tt.data)
			if got != tt.valid {
				t.Errorf("isValidMachO(%v) = %v, want %v", tt.data, got, tt.valid)
			}
		})
	}
}

func TestExecuteMemoryCommand_DefaultTimeout(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	// Valid Mach-O magic but not a real binary — will fail at execution, not validation
	fakeData := make([]byte, 100)
	fakeData[0] = 0xCF
	fakeData[1] = 0xFA
	fakeData[2] = 0xED
	fakeData[3] = 0xFE

	params, _ := json.Marshal(executeMemoryArgs{
		BinaryB64: base64.StdEncoding.EncodeToString(fakeData),
		Timeout:   0, // Should default to 60
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Will fail at execution (not a real binary) but should get past validation
	if result.Status != "error" {
		// Might succeed if the OS somehow runs empty Mach-O, but likely error
		return
	}
	// Should be an execution error, not a validation error
	if strings.Contains(result.Output, "binary_b64") || strings.Contains(result.Output, "too small") || strings.Contains(result.Output, "Mach-O") {
		t.Errorf("failed at validation stage, not execution: %s", result.Output)
	}
}

func TestExecuteMemoryCommand_NegativeTimeout(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	fakeData := make([]byte, 100)
	fakeData[0] = 0xCF
	fakeData[1] = 0xFA
	fakeData[2] = 0xED
	fakeData[3] = 0xFE

	params, _ := json.Marshal(executeMemoryArgs{
		BinaryB64: base64.StdEncoding.EncodeToString(fakeData),
		Timeout:   -5, // Should default to 60
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should get past validation (negative timeout defaults to 60)
	if strings.Contains(result.Output, "timeout") && strings.Contains(result.Output, "negative") {
		t.Error("should handle negative timeout gracefully")
	}
}
