//go:build linux

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestGetPrivsCommand_Name(t *testing.T) {
	cmd := &GetPrivsCommand{}
	if cmd.Name() != "getprivs" {
		t.Errorf("Expected 'getprivs', got '%s'", cmd.Name())
	}
}

func TestGetPrivsCommand_Description(t *testing.T) {
	cmd := &GetPrivsCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestGetPrivsCommand_ListAction(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}

	var output privsOutput
	if err := json.Unmarshal([]byte(result.Output), &output); err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	if output.Identity == "" {
		t.Error("Identity should not be empty")
	}
	if output.Source == "" {
		t.Error("Source should not be empty")
	}
	if output.Integrity == "" {
		t.Error("Integrity should not be empty")
	}
}

func TestGetPrivsCommand_EmptyParams(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("Expected success with empty params, got %s: %s", result.Status, result.Output)
	}
}

func TestGetPrivsCommand_InvalidJSON(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	// Falls back to list action
	if result.Status != "success" {
		t.Errorf("Expected success on invalid JSON fallback, got %s: %s", result.Status, result.Output)
	}
}

func TestGetPrivsCommand_UnsupportedActions(t *testing.T) {
	cmd := &GetPrivsCommand{}
	for _, action := range []string{"enable", "disable", "strip"} {
		result := cmd.Execute(structs.Task{Params: `{"action":"` + action + `"}`})
		if result.Status != "error" {
			t.Errorf("Action '%s' should return error on Linux, got %s", action, result.Status)
		}
	}
}

func TestGetPrivsCommand_UnknownAction(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"bogus"}`})
	if result.Status != "error" {
		t.Errorf("Expected error for unknown action, got %s", result.Status)
	}
}

func TestParseCapabilities(t *testing.T) {
	caps := parseCapabilities()
	// On a running Linux system, /proc/self/status should always have CapEff
	if _, ok := caps["CapEff"]; !ok {
		t.Error("Expected CapEff to be present")
	}
	if _, ok := caps["CapPrm"]; !ok {
		t.Error("Expected CapPrm to be present")
	}
	if _, ok := caps["CapBnd"]; !ok {
		t.Error("Expected CapBnd to be present")
	}
}

func TestDecodeCapabilities_AllCaps(t *testing.T) {
	// All 41 capabilities set
	var allCaps uint64 = (1 << 41) - 1
	entries := decodeCapabilities(allCaps, "CapEff")
	if len(entries) != 41 {
		t.Errorf("Expected 41 capabilities, got %d", len(entries))
	}
	// Check first and last
	if entries[0].Name != "CAP_CHOWN" {
		t.Errorf("Expected CAP_CHOWN first, got '%s'", entries[0].Name)
	}
	if entries[40].Name != "CAP_CHECKPOINT_RESTORE" {
		t.Errorf("Expected CAP_CHECKPOINT_RESTORE last, got '%s'", entries[40].Name)
	}
}

func TestDecodeCapabilities_NoCaps(t *testing.T) {
	entries := decodeCapabilities(0, "CapEff")
	if len(entries) != 0 {
		t.Errorf("Expected 0 capabilities for empty bitmask, got %d", len(entries))
	}
}

func TestDecodeCapabilities_SingleCap(t *testing.T) {
	// Only CAP_SYS_ADMIN (bit 21)
	entries := decodeCapabilities(1<<21, "CapEff")
	if len(entries) != 1 {
		t.Fatalf("Expected 1 capability, got %d", len(entries))
	}
	if entries[0].Name != "CAP_SYS_ADMIN" {
		t.Errorf("Expected CAP_SYS_ADMIN, got '%s'", entries[0].Name)
	}
	if entries[0].Status != "Enabled" {
		t.Errorf("Expected Enabled status, got '%s'", entries[0].Status)
	}
	if entries[0].Description == "" {
		t.Error("Expected non-empty description for CAP_SYS_ADMIN")
	}
}

func TestCapDescription(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"cap_sys_admin", "System administration (mount, sethostname, etc)"},
		{"cap_net_raw", "Use raw and packet sockets"},
		{"cap_chown", "Change file ownership"},
		{"unknown_cap", ""},
	}
	for _, tt := range tests {
		got := capDescription(tt.name)
		if got != tt.expected {
			t.Errorf("capDescription(%s): expected '%s', got '%s'", tt.name, tt.expected, got)
		}
	}
}

func TestGetSecurityContext(t *testing.T) {
	// Just verify it doesn't panic — actual result depends on system config
	ctx := getSecurityContext()
	_ = ctx
}
