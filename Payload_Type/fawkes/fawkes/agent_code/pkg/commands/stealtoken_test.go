//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestStealToken_Name(t *testing.T) {
	cmd := &StealTokenCommand{}
	if got := cmd.Name(); got != "steal-token" {
		t.Errorf("Name() = %q, want %q", got, "steal-token")
	}
}

func TestStealToken_ParamParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantPID int
	}{
		{"normal PID", `{"pid":1234}`, 1234},
		{"system PID 4", `{"pid":4}`, 4},
		{"high PID", `{"pid":65535}`, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params StealTokenParams
			if err := json.Unmarshal([]byte(tt.input), &params); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if params.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", params.PID, tt.wantPID)
			}
		})
	}
}

func TestStealToken_ZeroPID(t *testing.T) {
	cmd := &StealTokenCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid":0}`})
	if result.Status != "error" {
		t.Errorf("PID=0 should error, got status=%q", result.Status)
	}
	if result.Output != "PID is required" {
		t.Errorf("Output = %q, want %q", result.Output, "PID is required")
	}
}

func TestStealToken_InvalidJSON(t *testing.T) {
	cmd := &StealTokenCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestStealToken_MissingPID(t *testing.T) {
	cmd := &StealTokenCommand{}
	result := cmd.Execute(structs.Task{Params: `{}`})
	if result.Status != "error" {
		t.Errorf("Missing PID should error, got status=%q", result.Status)
	}
}
