//go:build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestExecuteMemoryWindowsCommand_Name(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	if cmd.Name() != "execute-memory" {
		t.Errorf("expected 'execute-memory', got %q", cmd.Name())
	}
}

func TestExecuteMemoryWindowsCommand_EmptyParams(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
	if !strings.Contains(result.Output, "binary_b64 parameter required") {
		t.Errorf("expected helpful error message, got: %s", result.Output)
	}
}

func TestExecuteMemoryWindowsCommand_InvalidJSON(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestExecuteMemoryWindowsCommand_EmptyBinary(t *testing.T) {
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

func TestExecuteMemoryWindowsCommand_InvalidBase64(t *testing.T) {
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

func TestExecuteMemoryWindowsCommand_TooSmall(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	smallData := base64.StdEncoding.EncodeToString([]byte{0x4D, 0x5A, 0x90})
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: smallData})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for too-small binary")
	}
	if !strings.Contains(result.Output, "too small") {
		t.Errorf("expected too-small error, got: %s", result.Output)
	}
}

func TestExecuteMemoryWindowsCommand_NotPE(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	// ELF magic (not PE)
	notPE := make([]byte, 128)
	notPE[0] = 0x7F
	notPE[1] = 'E'
	notPE[2] = 'L'
	notPE[3] = 'F'
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: base64.StdEncoding.EncodeToString(notPE)})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for non-PE binary")
	}
	if !strings.Contains(result.Output, "not a valid PE") {
		t.Errorf("expected PE validation error, got: %s", result.Output)
	}
}
