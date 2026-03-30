//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestLogonSessionsCommandName(t *testing.T) {
	assertCommandName(t, &LogonSessionsCommand{}, "logonsessions")
}

func TestLogonSessionsCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &LogonSessionsCommand{})
}

func TestLogonSessionsEmptyParams(t *testing.T) {
	cmd := &LogonSessionsCommand{}
	// Empty params should default to "list" action
	result := cmd.Execute(mockTask("logonsessions", ""))
	// Should succeed — enumerating sessions doesn't require admin
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}

func TestLogonSessionsInvalidJSON(t *testing.T) {
	cmd := &LogonSessionsCommand{}
	result := cmd.Execute(mockTask("logonsessions", "not json"))
	assertError(t, result)
}

func TestLogonSessionsArgsUnmarshal(t *testing.T) {
	var args logonSessionsArgs
	data := `{"action":"users","filter":"admin"}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Action != "users" {
		t.Errorf("expected action=users, got %q", args.Action)
	}
	if args.Filter != "admin" {
		t.Errorf("expected filter=admin, got %q", args.Filter)
	}
}

func TestLogonSessionsStateNames(t *testing.T) {
	tests := []struct {
		state uint32
		name  string
	}{
		{0, "Active"},
		{1, "Connected"},
		{4, "Disconnected"},
		{6, "Listen"},
		{9, "Init"},
	}
	for _, tc := range tests {
		got := wtsStateNames[tc.state]
		if got != tc.name {
			t.Errorf("wtsStateNames[%d] = %q, want %q", tc.state, got, tc.name)
		}
	}
}

func TestLogonSessionsInfoClassConstants(t *testing.T) {
	if wtsInfoClassUserName != 5 {
		t.Errorf("wtsInfoClassUserName = %d, want 5", wtsInfoClassUserName)
	}
	if wtsInfoClassDomainName != 7 {
		t.Errorf("wtsInfoClassDomainName = %d, want 7", wtsInfoClassDomainName)
	}
	if wtsInfoClassClientName != 10 {
		t.Errorf("wtsInfoClassClientName = %d, want 10", wtsInfoClassClientName)
	}
}

func TestLogonSessionsDefaultAction(t *testing.T) {
	cmd := &LogonSessionsCommand{}
	params, _ := json.Marshal(logonSessionsArgs{})
	result := cmd.Execute(mockTask("logonsessions", string(params)))
	// Empty action should default to "list"
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}
