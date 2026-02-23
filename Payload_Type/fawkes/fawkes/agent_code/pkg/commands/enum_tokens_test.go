//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestEnumTokensCommand_NameAndDescription(t *testing.T) {
	cmd := &EnumTokensCommand{}
	if cmd.Name() != "enum-tokens" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "enum-tokens")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestEnumTokensCommand_InvalidJSON(t *testing.T) {
	cmd := &EnumTokensCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestEnumTokensCommand_UnknownAction(t *testing.T) {
	cmd := &EnumTokensCommand{}
	params, _ := json.Marshal(enumTokensArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' in output, got: %s", result.Output)
	}
}

func TestEnumTokensCommand_ListDefault(t *testing.T) {
	cmd := &EnumTokensCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}

	// Should contain table headers
	if !strings.Contains(result.Output, "PID") {
		t.Error("output should contain 'PID' header")
	}
	if !strings.Contains(result.Output, "PROCESS") {
		t.Error("output should contain 'PROCESS' header")
	}
	if !strings.Contains(result.Output, "USER") {
		t.Error("output should contain 'USER' header")
	}

	// Should list at least the current process (we can always see ourselves)
	if !strings.Contains(result.Output, "Tokens enumerated:") {
		t.Error("output should contain 'Tokens enumerated:' count")
	}
}

func TestEnumTokensCommand_ListExplicit(t *testing.T) {
	cmd := &EnumTokensCommand{}
	params, _ := json.Marshal(enumTokensArgs{Action: "list"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestEnumTokensCommand_Unique(t *testing.T) {
	cmd := &EnumTokensCommand{}
	params, _ := json.Marshal(enumTokensArgs{Action: "unique"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should contain unique-specific headers
	if !strings.Contains(result.Output, "Unique token owners:") {
		t.Error("output should contain 'Unique token owners:' count")
	}
	if !strings.Contains(result.Output, "PROCS") {
		t.Error("output should contain 'PROCS' header")
	}
	if !strings.Contains(result.Output, "SESSIONS") {
		t.Error("output should contain 'SESSIONS' header")
	}
}

func TestEnumTokensCommand_UserFilter(t *testing.T) {
	cmd := &EnumTokensCommand{}
	// Filter for a user that definitely won't match
	params, _ := json.Marshal(enumTokensArgs{Action: "list", User: "NONEXISTENTUSER12345"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success even with no matches, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Filter: NONEXISTENTUSER12345") {
		t.Error("output should show the applied filter")
	}
	if !strings.Contains(result.Output, "Tokens enumerated: 0") {
		t.Error("no processes should match nonexistent user filter")
	}
}

func TestEnumTokensArgs_JSONParsing(t *testing.T) {
	input := `{"action":"unique","user":"SYSTEM"}`
	var args enumTokensArgs
	err := json.Unmarshal([]byte(input), &args)
	if err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if args.Action != "unique" {
		t.Errorf("Action = %q, want %q", args.Action, "unique")
	}
	if args.User != "SYSTEM" {
		t.Errorf("User = %q, want %q", args.User, "SYSTEM")
	}

	// Test empty JSON
	input = `{}`
	err = json.Unmarshal([]byte(input), &args)
	if err != nil {
		t.Fatalf("failed to parse empty JSON: %v", err)
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long string", 10, "this is..."},
		{"abc", 3, "abc"},
	}

	for _, tt := range tests {
		got := truncateStr(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateStr(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestIntegrityRank(t *testing.T) {
	tests := []struct {
		level string
		want  int
	}{
		{"System", 4},
		{"High", 3},
		{"Medium", 2},
		{"Low", 1},
		{"Unknown", 0},
		{"", 0},
	}

	for _, tt := range tests {
		got := integrityRank(tt.level)
		if got != tt.want {
			t.Errorf("integrityRank(%q) = %d, want %d", tt.level, got, tt.want)
		}
	}
}
