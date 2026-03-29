//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestKeylog_Name(t *testing.T) {
	cmd := &KeylogCommand{}
	if got := cmd.Name(); got != "keylog" {
		t.Errorf("Name() = %q, want %q", got, "keylog")
	}
}

func TestKeylog_Description(t *testing.T) {
	cmd := &KeylogCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestKeylog_EmptyParams(t *testing.T) {
	cmd := &KeylogCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("Empty params should error, got status=%q", result.Status)
	}
}

func TestKeylog_InvalidJSON(t *testing.T) {
	cmd := &KeylogCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestKeylog_UnknownAction(t *testing.T) {
	cmd := &KeylogCommand{}
	params, _ := json.Marshal(keylogArgs{Action: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Unknown action should error, got status=%q", result.Status)
	}
}

func TestKeylog_ParamParsing(t *testing.T) {
	tests := []struct {
		input  string
		action string
	}{
		{`{"action":"start"}`, "start"},
		{`{"action":"stop"}`, "stop"},
		{`{"action":"dump"}`, "dump"},
		{`{"action":"status"}`, "status"},
		{`{"action":"clear"}`, "clear"},
	}
	for _, tt := range tests {
		var args keylogArgs
		if err := json.Unmarshal([]byte(tt.input), &args); err != nil {
			t.Fatalf("JSON unmarshal failed for %q: %v", tt.input, err)
		}
		if args.Action != tt.action {
			t.Errorf("input %q: Action = %q, want %q", tt.input, args.Action, tt.action)
		}
	}
}

func TestKeylog_StatusWhenNotRunning(t *testing.T) {
	cmd := &KeylogCommand{}
	params, _ := json.Marshal(keylogArgs{Action: "status"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Status should succeed whether running or not
	if result.Status != "success" {
		t.Errorf("Status action should succeed, got status=%q output=%q", result.Status, result.Output)
	}
}

func TestKeylog_Constants(t *testing.T) {
	if WH_KEYBOARD_LL != 13 {
		t.Errorf("WH_KEYBOARD_LL = %d, want 13", WH_KEYBOARD_LL)
	}
	if WM_KEYDOWN != 0x0100 {
		t.Errorf("WM_KEYDOWN = 0x%X, want 0x0100", WM_KEYDOWN)
	}
}
