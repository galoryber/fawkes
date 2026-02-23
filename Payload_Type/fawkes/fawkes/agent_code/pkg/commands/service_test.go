//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/svc"
)

func TestServiceCommand_NameAndDescription(t *testing.T) {
	cmd := &ServiceCommand{}
	if cmd.Name() != "service" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "service")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if strings.Contains(cmd.Description(), "sc.exe") {
		t.Error("Description should not reference sc.exe (now uses SCM API)")
	}
}

func TestServiceCommand_EmptyParams(t *testing.T) {
	cmd := &ServiceCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestServiceCommand_InvalidJSON(t *testing.T) {
	cmd := &ServiceCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestServiceCommand_UnknownAction(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' in output, got: %s", result.Output)
	}
}

func TestServiceCommand_QueryNoName(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "query"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for query without name, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected 'name is required' in output, got: %s", result.Output)
	}
}

func TestServiceCommand_StartNoName(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "start"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for start without name, got %q", result.Status)
	}
}

func TestServiceCommand_StopNoName(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "stop"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for stop without name, got %q", result.Status)
	}
}

func TestServiceCommand_CreateNoName(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "create"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for create without name, got %q", result.Status)
	}
}

func TestServiceCommand_CreateNoBinpath(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "create", Name: "test"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for create without binpath, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "binpath") {
		t.Errorf("expected 'binpath' in error, got: %s", result.Output)
	}
}

func TestServiceCommand_DeleteNoName(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "delete"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for delete without name, got %q", result.Status)
	}
}

func TestServiceCommand_QueryExistingService(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "query", Name: "Spooler"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for Spooler query, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Service 'Spooler'") {
		t.Errorf("expected service header in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Binary Path") {
		t.Errorf("expected 'Binary Path' in output, got: %s", result.Output)
	}
}

func TestServiceCommand_QueryNonexistent(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "query", Name: "NonexistentServiceXYZ123"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent service, got %q: %s", result.Status, result.Output)
	}
}

func TestServiceCommand_List(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "list"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for service list, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Windows Services") {
		t.Errorf("expected 'Windows Services' in output, got: %s", result.Output)
	}
}

func TestServiceCommand_ActionCaseInsensitive(t *testing.T) {
	cmd := &ServiceCommand{}
	for _, action := range []string{"QUERY", "Query", "qUeRy"} {
		t.Run(action, func(t *testing.T) {
			params, _ := json.Marshal(serviceArgs{Action: action, Name: "Spooler"})
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "success" {
				t.Errorf("expected success for %q, got %q: %s", action, result.Status, result.Output)
			}
		})
	}
}

func TestDescribeServiceState(t *testing.T) {
	tests := []struct {
		state    svc.State
		expected string
	}{
		{svc.Stopped, "Stopped"},
		{svc.StartPending, "Starting"},
		{svc.StopPending, "Stopping"},
		{svc.Running, "Running"},
		{svc.ContinuePending, "Continuing"},
		{svc.PausePending, "Pausing"},
		{svc.Paused, "Paused"},
		{99, "Unknown(99)"},
	}
	for _, tt := range tests {
		result := describeServiceState(tt.state)
		if result != tt.expected {
			t.Errorf("describeServiceState(%d) = %q, want %q", tt.state, result, tt.expected)
		}
	}
}

func TestDescribeStartType(t *testing.T) {
	tests := []struct {
		startType uint32
		expected  string
	}{
		{0, "Boot"},
		{1, "System"},
		{2, "Automatic"},
		{3, "Manual"},
		{4, "Disabled"},
		{99, "Unknown(99)"},
	}
	for _, tt := range tests {
		result := describeStartType(tt.startType)
		if result != tt.expected {
			t.Errorf("describeStartType(%d) = %q, want %q", tt.startType, result, tt.expected)
		}
	}
}

func TestDescribeServiceType(t *testing.T) {
	tests := []struct {
		stype    uint32
		expected string
	}{
		{0x10, "Win32 Own Process"},
		{0x20, "Win32 Shared Process"},
		{0x01, "Kernel Driver"},
		{0x02, "File System Driver"},
	}
	for _, tt := range tests {
		result := describeServiceType(tt.stype)
		if result != tt.expected {
			t.Errorf("describeServiceType(0x%x) = %q, want %q", tt.stype, result, tt.expected)
		}
	}
}
