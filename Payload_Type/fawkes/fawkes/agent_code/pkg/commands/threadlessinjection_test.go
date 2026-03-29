//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestThreadlessInject_Name(t *testing.T) {
	cmd := &ThreadlessInjectCommand{}
	if got := cmd.Name(); got != "threadless-inject" {
		t.Errorf("Name() = %q, want %q", got, "threadless-inject")
	}
}

func TestThreadlessInject_Description(t *testing.T) {
	cmd := &ThreadlessInjectCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestThreadlessInject_EmptyParams(t *testing.T) {
	cmd := &ThreadlessInjectCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("Empty params should error, got status=%q", result.Status)
	}
}

func TestThreadlessInject_InvalidJSON(t *testing.T) {
	cmd := &ThreadlessInjectCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestThreadlessInject_MissingShellcode(t *testing.T) {
	cmd := &ThreadlessInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"pid":           1234,
		"dll_name":      "ntdll.dll",
		"function_name": "NtClose",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Missing shellcode should error, got status=%q", result.Status)
	}
}

func TestThreadlessInject_MissingPID(t *testing.T) {
	cmd := &ThreadlessInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"shellcode_b64": base64.StdEncoding.EncodeToString([]byte{0xCC}),
		"dll_name":      "ntdll.dll",
		"function_name": "NtClose",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Missing PID should error, got status=%q", result.Status)
	}
}

func TestThreadlessInject_InvalidBase64(t *testing.T) {
	cmd := &ThreadlessInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"shellcode_b64": "not-valid-base64!!!",
		"pid":           1234,
		"dll_name":      "ntdll.dll",
		"function_name": "NtClose",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestThreadlessInject_EmptyAfterDecode(t *testing.T) {
	cmd := &ThreadlessInjectCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"shellcode_b64": base64.StdEncoding.EncodeToString([]byte{}),
		"pid":           1234,
		"dll_name":      "ntdll.dll",
		"function_name": "NtClose",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Empty decoded shellcode should error, got status=%q", result.Status)
	}
}

func TestThreadlessInject_ParamParsing(t *testing.T) {
	input := `{"shellcode_b64":"AQID","pid":5678,"dll_name":"ntdll.dll","function_name":"NtClose"}`
	var params struct {
		ShellcodeB64 string `json:"shellcode_b64"`
		PID          int    `json:"pid"`
		DLLName      string `json:"dll_name"`
		FunctionName string `json:"function_name"`
	}
	if err := json.Unmarshal([]byte(input), &params); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if params.PID != 5678 {
		t.Errorf("PID = %d, want 5678", params.PID)
	}
	if params.DLLName != "ntdll.dll" {
		t.Errorf("DLLName = %q, want %q", params.DLLName, "ntdll.dll")
	}
	if params.FunctionName != "NtClose" {
		t.Errorf("FunctionName = %q, want %q", params.FunctionName, "NtClose")
	}
	decoded, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(decoded) != 3 {
		t.Errorf("Decoded len = %d, want 3", len(decoded))
	}
}

func TestBuildLoaderStub_Deterministic(t *testing.T) {
	// buildLoaderStub uses randomization — verify it always produces valid output
	for i := 0; i < 10; i++ {
		stub, offset := buildLoaderStub()
		if len(stub) == 0 {
			t.Fatal("buildLoaderStub returned empty stub")
		}
		if offset <= 0 || offset >= len(stub) {
			t.Errorf("offset %d out of range [1, %d)", offset, len(stub))
		}
		// Verify the placeholder bytes are present at the offset
		if offset+8 > len(stub) {
			t.Errorf("offset %d + 8 exceeds stub length %d", offset, len(stub))
		}
	}
}

func TestGenerateHook_PatchesBytes(t *testing.T) {
	// Prepare a stub
	stub, offset := buildLoaderStub()
	threadlessPayload = make([]byte, len(stub))
	copy(threadlessPayload, stub)

	original := []byte{0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83}
	generateHook(original, offset)

	for i, b := range original {
		if threadlessPayload[offset+i] != b {
			t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, threadlessPayload[offset+i], b)
		}
	}
}
