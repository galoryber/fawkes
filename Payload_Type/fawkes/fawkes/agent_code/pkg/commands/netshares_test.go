//go:build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetEnumSharesLocal(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "shares"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for local shares, got %q: %s", result.Status, result.Output)
	}
}

func TestNetEnumSharesRemote(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "shares", Target: "127.0.0.1"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Remote shares to localhost — may succeed or fail gracefully
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestNetEnumMappedDrives(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "mapped"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for mapped drives, got %q: %s", result.Status, result.Output)
	}
}

func TestNetEnumUnknownAction(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
}

func TestNeDescribeShareType(t *testing.T) {
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
		result := neDescribeShareType(tt.stype)
		if result != tt.expected {
			t.Errorf("neDescribeShareType(0x%x) = %q, want %q", tt.stype, result, tt.expected)
		}
	}
}
