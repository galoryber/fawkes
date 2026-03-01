//go:build linux

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
	// 3 bytes - too small to be valid ELF
	smallData := base64.StdEncoding.EncodeToString([]byte{0x7f, 0x45, 0x4c})
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: smallData})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for too-small binary")
	}
	if !strings.Contains(result.Output, "too small") {
		t.Errorf("expected too-small error, got: %s", result.Output)
	}
}

func TestExecuteMemoryCommand_NotELF(t *testing.T) {
	cmd := &ExecuteMemoryCommand{}
	// 4+ bytes but not ELF magic
	notElf := base64.StdEncoding.EncodeToString([]byte{0x4d, 0x5a, 0x90, 0x00, 0x03}) // PE magic
	params, _ := json.Marshal(executeMemoryArgs{BinaryB64: notElf})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for non-ELF binary")
	}
	if !strings.Contains(result.Output, "not a valid ELF") {
		t.Errorf("expected ELF validation error, got: %s", result.Output)
	}
}
