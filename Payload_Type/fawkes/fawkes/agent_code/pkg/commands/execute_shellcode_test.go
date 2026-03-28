//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestExecuteShellcode_Name(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	if got := cmd.Name(); got != "execute-shellcode" {
		t.Errorf("Name() = %q, want %q", got, "execute-shellcode")
	}
}

func TestExecuteShellcode_EmptyParams(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("Empty params should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcode_InvalidJSON(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcode_EmptyShellcode(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	params, _ := json.Marshal(executeShellcodeArgs{ShellcodeB64: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Empty shellcode should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcode_InvalidBase64(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	params, _ := json.Marshal(executeShellcodeArgs{ShellcodeB64: "not-valid-base64!!!"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcode_EmptyAfterDecode(t *testing.T) {
	cmd := &ExecuteShellcodeCommand{}
	// base64 of empty bytes
	params, _ := json.Marshal(executeShellcodeArgs{ShellcodeB64: base64.StdEncoding.EncodeToString([]byte{})})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Empty decoded shellcode should error, got status=%q", result.Status)
	}
}

func TestExecuteShellcode_ParamParsing(t *testing.T) {
	// Verify the struct unmarshal works correctly
	input := `{"shellcode_b64":"AQID"}`
	var args executeShellcodeArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if args.ShellcodeB64 != "AQID" {
		t.Errorf("ShellcodeB64 = %q, want %q", args.ShellcodeB64, "AQID")
	}
	decoded, err := base64.StdEncoding.DecodeString(args.ShellcodeB64)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(decoded) != 3 || decoded[0] != 1 || decoded[1] != 2 || decoded[2] != 3 {
		t.Errorf("Decoded = %v, want [1 2 3]", decoded)
	}
}
