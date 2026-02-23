//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetSharesCommand_NameAndDescription(t *testing.T) {
	cmd := &NetSharesCommand{}
	if cmd.Name() != "net-shares" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "net-shares")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if strings.Contains(cmd.Description(), "net.exe") {
		t.Error("Description should not reference net.exe (now uses Win32 API)")
	}
}

func TestNetSharesCommand_EmptyParams(t *testing.T) {
	cmd := &NetSharesCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestNetSharesCommand_InvalidJSON(t *testing.T) {
	cmd := &NetSharesCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestNetSharesCommand_UnknownAction(t *testing.T) {
	cmd := &NetSharesCommand{}
	params, _ := json.Marshal(netSharesArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "local") {
		t.Error("error should list available actions")
	}
}

func TestNetSharesCommand_RemoteNoTarget(t *testing.T) {
	cmd := &NetSharesCommand{}
	params, _ := json.Marshal(netSharesArgs{Action: "remote"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for remote without target, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "target") {
		t.Errorf("expected 'target' in error message, got: %s", result.Output)
	}
}

func TestNetSharesCommand_LocalShares(t *testing.T) {
	cmd := &NetSharesCommand{}
	params, _ := json.Marshal(netSharesArgs{Action: "local"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for local shares, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Local Shares") && !strings.Contains(result.Output, "No local shares") {
		t.Errorf("expected share listing in output, got: %s", result.Output)
	}
}

func TestNetSharesCommand_MappedDrives(t *testing.T) {
	cmd := &NetSharesCommand{}
	params, _ := json.Marshal(netSharesArgs{Action: "mapped"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for mapped drives, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Mapped Drives") {
		t.Errorf("expected 'Mapped Drives' in output, got: %s", result.Output)
	}
}

func TestNetSharesCommand_ActionCaseInsensitive(t *testing.T) {
	cmd := &NetSharesCommand{}
	for _, action := range []string{"LOCAL", "Local", "lOcAl"} {
		t.Run(action, func(t *testing.T) {
			params, _ := json.Marshal(netSharesArgs{Action: action})
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "success" {
				t.Errorf("expected success for %q, got %q: %s", action, result.Status, result.Output)
			}
		})
	}
}

func TestDescribeShareType(t *testing.T) {
	tests := []struct {
		stype    uint32
		expected string
	}{
		{STYPE_DISKTREE, "Disk"},
		{STYPE_PRINTQ, "Print"},
		{STYPE_DEVICE, "Device"},
		{STYPE_IPC, "IPC"},
		{STYPE_DISKTREE | STYPE_SPECIAL, "Disk (Admin)"},
		{STYPE_IPC | STYPE_SPECIAL, "IPC (Admin)"},
		{STYPE_DISKTREE | STYPE_TEMPORARY, "Disk (Temp)"},
		{STYPE_DISKTREE | STYPE_SPECIAL | STYPE_TEMPORARY, "Disk (Admin) (Temp)"},
	}
	for _, tt := range tests {
		result := describeShareType(tt.stype)
		if result != tt.expected {
			t.Errorf("describeShareType(0x%x) = %q, want %q", tt.stype, result, tt.expected)
		}
	}
}
