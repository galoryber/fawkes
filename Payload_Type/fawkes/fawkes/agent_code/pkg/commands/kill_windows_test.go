//go:build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestKillCommand_Name(t *testing.T) {
	cmd := &KillCommand{}
	if cmd.Name() != "kill" {
		t.Errorf("Name() = %q, want kill", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestKillCommand_InvalidPID(t *testing.T) {
	cmd := &KillCommand{}

	tests := []struct {
		name   string
		params string
	}{
		{"zero PID", `{"pid":0}`},
		{"negative PID", `{"pid":-1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := structs.Task{
				ID:     "test-kill",
				Params: tt.params,
			}
			result := cmd.Execute(task)
			if result.Status != "error" {
				t.Errorf("expected error status for %s, got %s", tt.name, result.Status)
			}
		})
	}
}

func TestKillCommand_InvalidJSON(t *testing.T) {
	cmd := &KillCommand{}
	task := structs.Task{
		ID:     "test-kill",
		Params: "not json",
	}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %s", result.Status)
	}
}

func TestKillParams_JSONSerialization(t *testing.T) {
	params := KillParams{PID: 4567}
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	var decoded KillParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PID != 4567 {
		t.Errorf("PID = %d, want 4567", decoded.PID)
	}
}
