//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestSyscallsCommandName(t *testing.T) {
	cmd := &SyscallsCommand{}
	if cmd.Name() != "syscalls" {
		t.Errorf("Name() = %q, want syscalls", cmd.Name())
	}
}

func TestSyscallsCommandDescription(t *testing.T) {
	cmd := &SyscallsCommand{}
	if cmd.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestSyscallsParams_JSON(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		action string
	}{
		{"status", `{"action":"status"}`, "status"},
		{"list", `{"action":"list"}`, "list"},
		{"init", `{"action":"init"}`, "init"},
		{"empty", `{}`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p syscallsParams
			if err := json.Unmarshal([]byte(tt.json), &p); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if p.Action != tt.action {
				t.Errorf("Action = %q, want %q", p.Action, tt.action)
			}
		})
	}
}

func TestSyscallsParams_RoundTrip(t *testing.T) {
	original := syscallsParams{Action: "list"}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded syscallsParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Action != original.Action {
		t.Errorf("round-trip Action = %q, want %q", decoded.Action, original.Action)
	}
}
