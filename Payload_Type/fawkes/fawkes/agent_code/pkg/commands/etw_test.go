//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestEtw_Name(t *testing.T) {
	cmd := &EtwCommand{}
	if got := cmd.Name(); got != "etw" {
		t.Errorf("Name() = %q, want %q", got, "etw")
	}
}

func TestEtw_Description(t *testing.T) {
	cmd := &EtwCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestEtw_InvalidJSON(t *testing.T) {
	cmd := &EtwCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestEtw_UnknownAction(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Unknown action should error, got status=%q", result.Status)
	}
}

func TestEtw_StopRequiresSessionName(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "stop"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Stop without session_name should error, got status=%q", result.Status)
	}
}

func TestEtw_BlindRequiresSessionName(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "blind", Provider: "sysmon"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Blind without session_name should error, got status=%q", result.Status)
	}
}

func TestEtw_BlindRequiresProvider(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "blind", SessionName: "TestSession"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Blind without provider should error, got status=%q", result.Status)
	}
}

func TestEtw_QueryRequiresSessionName(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "query"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Query without session_name should error, got status=%q", result.Status)
	}
}

func TestEtw_EnableRequiresSessionName(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "enable", Provider: "sysmon"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Enable without session_name should error, got status=%q", result.Status)
	}
}

func TestEtw_EnableRequiresProvider(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "enable", SessionName: "TestSession"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Enable without provider should error, got status=%q", result.Status)
	}
}

func TestEtw_ParamParsing(t *testing.T) {
	tests := []struct {
		input       string
		action      string
		sessionName string
		provider    string
	}{
		{`{"action":"sessions"}`, "sessions", "", ""},
		{`{"action":"stop","session_name":"EventLog-Security"}`, "stop", "EventLog-Security", ""},
		{`{"action":"blind","session_name":"Sysmon","provider":"sysmon"}`, "blind", "Sysmon", "sysmon"},
		{`{"action":"query","session_name":"TestSession"}`, "query", "TestSession", ""},
	}
	for _, tt := range tests {
		var params etwParams
		if err := json.Unmarshal([]byte(tt.input), &params); err != nil {
			t.Fatalf("JSON unmarshal failed for %q: %v", tt.input, err)
		}
		if params.Action != tt.action {
			t.Errorf("input %q: Action = %q, want %q", tt.input, params.Action, tt.action)
		}
		if params.SessionName != tt.sessionName {
			t.Errorf("input %q: SessionName = %q, want %q", tt.input, params.SessionName, tt.sessionName)
		}
		if params.Provider != tt.provider {
			t.Errorf("input %q: Provider = %q, want %q", tt.input, params.Provider, tt.provider)
		}
	}
}

func TestEtw_Constants(t *testing.T) {
	if eventTraceControlStop != 1 {
		t.Errorf("eventTraceControlStop = %d, want 1", eventTraceControlStop)
	}
	if eventControlCodeDisableProvider != 0 {
		t.Errorf("eventControlCodeDisableProvider = %d, want 0", eventControlCodeDisableProvider)
	}
	if eventControlCodeEnableProvider != 1 {
		t.Errorf("eventControlCodeEnableProvider = %d, want 1", eventControlCodeEnableProvider)
	}
}
