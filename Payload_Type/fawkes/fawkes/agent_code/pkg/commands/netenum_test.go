//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetEnumCommand_NameAndDescription(t *testing.T) {
	cmd := &NetEnumCommand{}
	if cmd.Name() != "net-enum" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "net-enum")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if strings.Contains(cmd.Description(), "net.exe") {
		t.Error("Description should not reference net.exe (now uses Win32 API)")
	}
}

func TestNetEnumCommand_EmptyParams(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestNetEnumCommand_InvalidJSON(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestNetEnumCommand_UnknownAction(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "users") {
		t.Error("error should list available actions")
	}
}

func TestNetEnumCommand_GroupMembersNoTarget(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "groupmembers"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for groupmembers without target, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "target") {
		t.Errorf("expected 'target' in error message, got: %s", result.Output)
	}
}

func TestNetEnumCommand_LocalUsers(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "users"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for local users, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Local Users") {
		t.Errorf("expected 'Local Users' in output, got: %s", result.Output)
	}
	// Should always have at least Administrator
	if !strings.Contains(result.Output, "Administrator") {
		t.Logf("Warning: Administrator not found in output (may be renamed): %s", result.Output)
	}
}

func TestNetEnumCommand_LocalGroups(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "localgroups"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for local groups, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Local Groups") {
		t.Errorf("expected 'Local Groups' in output, got: %s", result.Output)
	}
	// Should always have Administrators group
	if !strings.Contains(result.Output, "Administrators") {
		t.Logf("Warning: Administrators group not found in output: %s", result.Output)
	}
}

func TestNetEnumCommand_GroupMembers(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "groupmembers", Target: "Administrators"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for group members, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Members of 'Administrators'") {
		t.Errorf("expected members header in output, got: %s", result.Output)
	}
}

func TestNetEnumCommand_GroupMembersNonexistent(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "groupmembers", Target: "NonexistentGroupXYZ123"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent group, got %q: %s", result.Status, result.Output)
	}
}

func TestNetEnumCommand_ActionCaseInsensitive(t *testing.T) {
	cmd := &NetEnumCommand{}
	for _, action := range []string{"USERS", "Users", "uSeRs"} {
		t.Run(action, func(t *testing.T) {
			params, _ := json.Marshal(netEnumArgs{Action: action})
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "success" {
				t.Errorf("expected success for %q, got %q: %s", action, result.Status, result.Output)
			}
		})
	}
}

func TestNetEnumCommand_DomainInfo(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "domaininfo"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Either success (domain-joined) or error/success with "not domain-joined" message
	if result.Status == "error" {
		if !strings.Contains(result.Output, "domain") {
			t.Errorf("expected domain-related error, got: %s", result.Output)
		}
	}
	// Command should always complete
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestDescribeTrustFlags(t *testing.T) {
	tests := []struct {
		flags    uint32
		contains []string
	}{
		{DS_DOMAIN_PRIMARY, []string{"Primary"}},
		{DS_DOMAIN_IN_FOREST, []string{"InForest"}},
		{DS_DOMAIN_DIRECT_OUTBOUND | DS_DOMAIN_DIRECT_INBOUND, []string{"DirectOutbound", "DirectInbound"}},
		{DS_DOMAIN_PRIMARY | DS_DOMAIN_IN_FOREST | DS_DOMAIN_NATIVE_MODE, []string{"Primary", "InForest", "NativeMode"}},
		{0, []string{"flags=0x0"}},
	}
	for _, tt := range tests {
		result := describeTrustFlags(tt.flags)
		for _, s := range tt.contains {
			if !strings.Contains(result, s) {
				t.Errorf("describeTrustFlags(0x%x) = %q, expected to contain %q", tt.flags, result, s)
			}
		}
	}
}
