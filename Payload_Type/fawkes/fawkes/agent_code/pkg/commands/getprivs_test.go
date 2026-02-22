//go:build windows

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestGetPrivsCommand_NameAndDescription(t *testing.T) {
	cmd := &GetPrivsCommand{}
	if cmd.Name() != "getprivs" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "getprivs")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestGetPrivsCommand_Execute(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	// Should succeed — we can always read our own process token
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}

	// Output should contain key sections
	if !strings.Contains(result.Output, "Token:") {
		t.Error("output should contain 'Token:'")
	}
	if !strings.Contains(result.Output, "Integrity:") {
		t.Error("output should contain 'Integrity:'")
	}
	if !strings.Contains(result.Output, "Privileges:") {
		t.Error("output should contain 'Privileges:'")
	}
	if !strings.Contains(result.Output, "PRIVILEGE") {
		t.Error("output should contain header 'PRIVILEGE'")
	}
	if !strings.Contains(result.Output, "STATUS") {
		t.Error("output should contain header 'STATUS'")
	}

	// Should list at least SeChangeNotifyPrivilege (present on all tokens)
	if !strings.Contains(result.Output, "SeChangeNotifyPrivilege") {
		t.Error("output should list SeChangeNotifyPrivilege (present on all tokens)")
	}
}

func TestGetPrivsCommand_HasDescriptions(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Skipf("skipping — could not enumerate privs: %s", result.Output)
	}

	// SeChangeNotifyPrivilege should have a description
	if !strings.Contains(result.Output, "Bypass traverse checking") {
		t.Error("output should include description for SeChangeNotifyPrivilege")
	}
}

func TestGetPrivsCommand_EnabledCount(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Skipf("skipping: %s", result.Output)
	}

	// Should contain "Enabled: X / Y"
	if !strings.Contains(result.Output, "Enabled:") {
		t.Error("output should contain 'Enabled:' count line")
	}
}

func TestPrivilegeDescription_Known(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"SeDebugPrivilege", "Debug programs"},
		{"SeImpersonatePrivilege", "Impersonate a client after authentication"},
		{"SeBackupPrivilege", "Back up files and directories"},
		{"SeShutdownPrivilege", "Shut down the system"},
	}

	for _, tt := range tests {
		got := privilegeDescription(tt.name)
		if got != tt.want {
			t.Errorf("privilegeDescription(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestPrivilegeDescription_Unknown(t *testing.T) {
	got := privilegeDescription("SeNonExistentPrivilege")
	if got != "" {
		t.Errorf("privilegeDescription for unknown should return empty, got %q", got)
	}
}
