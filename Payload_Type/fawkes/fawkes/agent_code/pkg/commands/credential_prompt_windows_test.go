//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"
	"unsafe"

	"fawkes/pkg/structs"
)

func TestCredentialPromptCommand_Name(t *testing.T) {
	cmd := &CredentialPromptCommand{}
	if cmd.Name() != "credential-prompt" {
		t.Errorf("expected 'credential-prompt', got %q", cmd.Name())
	}
}

func TestCredentialPromptCommand_Description(t *testing.T) {
	cmd := &CredentialPromptCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("description should not be empty")
	}
	if !containsStr(desc, "T1056") {
		t.Error("description should reference MITRE ATT&CK technique")
	}
}

func TestCredentialPromptCommand_InvalidJSON(t *testing.T) {
	cmd := &CredentialPromptCommand{}
	task := structs.Task{Params: "{bad json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestCredUIInfoW_Size(t *testing.T) {
	// credUIInfoW on 64-bit: 4+4+8+8+8+8 = 40 bytes
	size := unsafe.Sizeof(credUIInfoW{})
	if size != 40 {
		t.Errorf("credUIInfoW size: expected 40, got %d", size)
	}
}

func TestCredUIInfoW_CbSize(t *testing.T) {
	info := credUIInfoW{}
	info.cbSize = uint32(unsafe.Sizeof(credUIInfoW{}))
	if info.cbSize != 40 {
		t.Errorf("cbSize: expected 40, got %d", info.cbSize)
	}
}

func TestCredentialPromptConstants(t *testing.T) {
	if creduiwinGeneric != 0x1 {
		t.Errorf("creduiwinGeneric: expected 0x1, got 0x%X", creduiwinGeneric)
	}
	if errorSuccess != 0 {
		t.Errorf("errorSuccess: expected 0, got %d", errorSuccess)
	}
	if errorCancelled != 1223 {
		t.Errorf("errorCancelled: expected 1223, got %d", errorCancelled)
	}
	if credMaxStringLen != 256 {
		t.Errorf("credMaxStringLen: expected 256, got %d", credMaxStringLen)
	}
}

func TestCredentialPromptParams_Parse(t *testing.T) {
	var args struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	}

	data := []byte(`{"title":"Security Alert","message":"Please authenticate"}`)
	if err := json.Unmarshal(data, &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Title != "Security Alert" {
		t.Errorf("title: expected 'Security Alert', got %q", args.Title)
	}
	if args.Message != "Please authenticate" {
		t.Errorf("message: expected 'Please authenticate', got %q", args.Message)
	}
}

func TestCredentialPromptParams_Defaults(t *testing.T) {
	var args struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	}

	// Empty params should result in empty fields (defaults applied in Execute)
	data := []byte(`{}`)
	if err := json.Unmarshal(data, &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Title != "" {
		t.Errorf("title should be empty (default applied in Execute), got %q", args.Title)
	}
}
