//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetSessionCommandName(t *testing.T) {
	cmd := &NetSessionCommand{}
	if cmd.Name() != "net-session" {
		t.Errorf("expected 'net-session', got '%s'", cmd.Name())
	}
}

func TestNetSessionCommandDescription(t *testing.T) {
	cmd := &NetSessionCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("description should not be empty")
	}
}

func TestNetSessionEmptyParams(t *testing.T) {
	cmd := &NetSessionCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	// With empty params, targets localhost — should succeed or fail gracefully
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestNetSessionInvalidJSON(t *testing.T) {
	cmd := &NetSessionCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status for invalid JSON, got '%s'", result.Status)
	}
	if result.Completed != true {
		t.Error("expected completed=true on error")
	}
}

func TestNetSessionValidJSON(t *testing.T) {
	cmd := &NetSessionCommand{}
	params, _ := json.Marshal(map[string]string{"target": ""})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should succeed locally or fail gracefully
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestNetSessionRemoteTarget(t *testing.T) {
	cmd := &NetSessionCommand{}
	params, _ := json.Marshal(map[string]string{"target": "127.0.0.1"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestSesFormatDuration(t *testing.T) {
	tests := []struct {
		seconds  uint32
		expected string
	}{
		{0, "0s"},
		{30, "30s"},
		{59, "59s"},
		{60, "1m0s"},
		{90, "1m30s"},
		{3600, "1h0m"},
		{3661, "1h1m"},
		{7200, "2h0m"},
	}
	for _, tt := range tests {
		result := sesFormatDuration(tt.seconds)
		if result != tt.expected {
			t.Errorf("sesFormatDuration(%d) = %s, want %s", tt.seconds, result, tt.expected)
		}
	}
}
