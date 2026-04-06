//go:build linux || darwin
// +build linux darwin

package commands

import (
	"encoding/json"
	"runtime"
	"testing"

	"fawkes/pkg/structs"
)

func TestEtwUnix_Name(t *testing.T) {
	cmd := &EtwCommand{}
	if got := cmd.Name(); got != "etw" {
		t.Errorf("Name() = %q, want %q", got, "etw")
	}
}

func TestEtwUnix_Description(t *testing.T) {
	cmd := &EtwCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestEtwUnix_InvalidJSON(t *testing.T) {
	cmd := &EtwCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestEtwUnix_UnknownAction(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "invalid_action"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Unknown action should error, got status=%q", result.Status)
	}
}

func TestEtwUnix_DisableRuleRequiresSpec(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("disable-rule only on Linux")
	}
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "disable-rule", SessionName: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("disable-rule without rule spec should error, got status=%q", result.Status)
	}
}

func TestEtwUnix_AgentsReturnsJSON(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "agents"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("agents should succeed, got status=%q output=%s", result.Status, result.Output)
	}
	// Output should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Output), &parsed); err != nil {
		t.Errorf("agents output should be valid JSON: %v", err)
	}
}

func TestEtwUnix_ParamParsing(t *testing.T) {
	tests := []struct {
		input  string
		action string
	}{
		{`{"action":"rules"}`, "rules"},
		{`{"action":"agents"}`, "agents"},
		{`{"action":"audit-status"}`, "audit-status"},
		{`{"action":"syslog-config"}`, "syslog-config"},
	}
	for _, tt := range tests {
		var params etwParams
		if err := json.Unmarshal([]byte(tt.input), &params); err != nil {
			t.Fatalf("JSON unmarshal failed for %q: %v", tt.input, err)
		}
		if params.Action != tt.action {
			t.Errorf("input %q: Action = %q, want %q", tt.input, params.Action, tt.action)
		}
	}
}

func TestEtwUnix_SyslogConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("syslog-config only on Linux")
	}
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "syslog-config"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should succeed (even if no syslog config exists — will show headers)
	if result.Status != "success" {
		t.Errorf("syslog-config should succeed, got status=%q", result.Status)
	}
}


func TestEtwUnix_DefaultAction(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Default action should run without error (rules on Linux, categories on macOS)
	// May fail due to permissions but should not be "unknown action"
	_ = result // Just ensure no panic
}
