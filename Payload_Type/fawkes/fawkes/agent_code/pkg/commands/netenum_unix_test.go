//go:build linux || darwin
// +build linux darwin

package commands

import (
	"encoding/json"
	"runtime"
	"testing"

	"fawkes/pkg/structs"
)

func neTestTask(params string) structs.Task {
	return structs.NewTask("test-ne", "net-enum", params)
}

func TestNetEnumUsers(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(neTestTask(`{"action":"users"}`))
	if result.Status != "success" {
		t.Fatalf("users failed: %s", result.Output)
	}
	var entries []netEnumEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one user")
	}
	foundRoot := false
	for _, e := range entries {
		if e.Name == "root" {
			foundRoot = true
			if e.UID != 0 {
				t.Errorf("root UID = %d, want 0", e.UID)
			}
		}
	}
	if runtime.GOOS == "linux" && !foundRoot {
		t.Error("root user not found")
	}
}

func TestNetEnumGroups(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(neTestTask(`{"action":"groups"}`))
	if result.Status != "success" {
		t.Fatalf("groups failed: %s", result.Output)
	}
	var entries []netEnumEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one group")
	}
}

func TestNetEnumGroupMembers(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(neTestTask(`{"action":"groupmembers","group":"root"}`))
	if result.Status != "success" {
		t.Fatalf("groupmembers failed: %s", result.Output)
	}
	var entries []netEnumEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	foundRoot := false
	for _, e := range entries {
		if e.Name == "root" {
			foundRoot = true
		}
	}
	if runtime.GOOS == "linux" && !foundRoot {
		t.Error("root not found as member of root group")
	}
}

func TestNetEnumAdmins(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(neTestTask(`{"action":"admins"}`))
	if result.Status != "success" {
		t.Fatalf("admins failed: %s", result.Output)
	}
	var entries []netEnumEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	foundRoot := false
	for _, e := range entries {
		if e.Name == "root" {
			foundRoot = true
		}
	}
	if !foundRoot {
		t.Error("root not found in admins")
	}
}

func TestNetEnumSessions(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(neTestTask(`{"action":"sessions"}`))
	if result.Status != "success" {
		t.Fatalf("sessions failed: %s", result.Output)
	}
	var entries []netEnumEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse sessions: %v", err)
	}
}

func TestNetEnumShares(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(neTestTask(`{"action":"shares"}`))
	if result.Status != "success" {
		t.Fatalf("shares failed: %s", result.Output)
	}
	var entries []netEnumEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse shares: %v", err)
	}
}

func TestNetEnumUnsupported(t *testing.T) {
	cmd := &NetEnumCommand{}
	for _, action := range []string{"domainusers", "domaingroups", "domaininfo", "mapped"} {
		t.Run(action, func(t *testing.T) {
			result := cmd.Execute(neTestTask(`{"action":"` + action + `"}`))
			if result.Status == "success" {
				t.Errorf("%s should not be supported on %s", action, runtime.GOOS)
			}
		})
	}
}

func TestNetEnumGroupMembersNoGroup(t *testing.T) {
	cmd := &NetEnumCommand{}
	result := cmd.Execute(neTestTask(`{"action":"groupmembers"}`))
	if result.Status == "success" {
		t.Error("groupmembers without -group should fail")
	}
}
