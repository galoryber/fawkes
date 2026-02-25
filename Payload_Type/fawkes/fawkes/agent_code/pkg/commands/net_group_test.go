package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetGroupName(t *testing.T) {
	cmd := &NetGroupCommand{}
	if cmd.Name() != "net-group" {
		t.Errorf("expected net-group, got %s", cmd.Name())
	}
}

func TestNetGroupDescription(t *testing.T) {
	cmd := &NetGroupCommand{}
	if !strings.Contains(cmd.Description(), "T1069") {
		t.Error("description should mention MITRE T1069")
	}
}

func TestNetGroupEmptyParams(t *testing.T) {
	cmd := &NetGroupCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("empty params should return error")
	}
}

func TestNetGroupBadJSON(t *testing.T) {
	cmd := &NetGroupCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("bad JSON should return error")
	}
}

func TestNetGroupMissingServer(t *testing.T) {
	cmd := &NetGroupCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "server") {
		t.Error("missing server should return error mentioning server")
	}
}

func TestNetGroupInvalidAction(t *testing.T) {
	cmd := &NetGroupCommand{}
	// Will fail on connection before action check
	result := cmd.Execute(structs.Task{Params: `{"action":"badaction","server":"192.0.2.1"}`})
	if result.Status != "error" {
		t.Error("should return error")
	}
}

func TestNetGroupMembersMissingGroup(t *testing.T) {
	cmd := &NetGroupCommand{}
	// Will fail on connection, but if it got through, should require group param
	result := cmd.Execute(structs.Task{Params: `{"action":"members","server":"192.0.2.1"}`})
	if result.Status != "error" {
		t.Error("members without group should return error")
	}
}

func TestNetGroupUserMissingUser(t *testing.T) {
	cmd := &NetGroupCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"user","server":"192.0.2.1"}`})
	if result.Status != "error" {
		t.Error("user without user param should return error")
	}
}

func TestNgGroupTypeStr(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"-2147483646", "[Global Security]"},      // 0x80000002
		{"-2147483644", "[Domain Local Security]"}, // 0x80000004
		{"-2147483640", "[Universal Security]"},    // 0x80000008
		{"2", "[Global Distribution]"},
		{"4", "[Domain Local Distribution]"},
		{"8", "[Universal Distribution]"},
		{"", "[?]"},
		{"abc", "[?]"},
	}

	for _, tt := range tests {
		result := ngGroupTypeStr(tt.input)
		if result != tt.expected {
			t.Errorf("ngGroupTypeStr(%q): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestNgContainsClass(t *testing.T) {
	classes := []string{"top", "person", "organizationalPerson", "user"}

	if !ngContainsClass(classes, "user") {
		t.Error("should find 'user'")
	}
	if !ngContainsClass(classes, "User") {
		t.Error("should find 'User' (case insensitive)")
	}
	if ngContainsClass(classes, "computer") {
		t.Error("should not find 'computer'")
	}
	if ngContainsClass(nil, "user") {
		t.Error("should handle nil")
	}
}

func TestPrivilegedGroupsList(t *testing.T) {
	// Verify key privileged groups are in the list
	expected := []string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"}
	for _, e := range expected {
		found := false
		for _, pg := range privilegedGroups {
			if pg == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("privilegedGroups should contain %q", e)
		}
	}
}

func TestNetGroupDefaultPort(t *testing.T) {
	cmd := &NetGroupCommand{}

	// Default port 389
	result := cmd.Execute(structs.Task{Params: `{"action":"list","server":"192.0.2.1"}`})
	if !strings.Contains(result.Output, "389") {
		t.Errorf("default port should be 389, got: %s", result.Output)
	}

	// TLS port 636
	result = cmd.Execute(structs.Task{Params: `{"action":"list","server":"192.0.2.1","use_tls":true}`})
	if !strings.Contains(result.Output, "636") {
		t.Errorf("TLS port should be 636, got: %s", result.Output)
	}
}
