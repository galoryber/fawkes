package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestLastReturnsJSON(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	var entries []lastLoginEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Errorf("expected valid JSON output: %v (got: %s)", err, result.Output)
	}
}

func TestLastWithEmptyJSON(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: "{}"})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastWithCount(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Count: 5})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastWithUserFilter(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Count: 10, User: "nonexistentuser12345"})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastDefaultCount(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Count: -1})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastFailedAction(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action": "failed"}`})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	var entries []lastLoginEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Errorf("expected valid JSON output: %v (got: %s)", err, result.Output)
	}
}

func TestLastLoginsAction(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action": "logins"}`})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastRebootAction(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action": "reboot"}`})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	var entries []lastLoginEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Errorf("expected valid JSON output: %v (got: %s)", err, result.Output)
	}
}

func TestLastRebootActionUpperCase(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action": "REBOOT"}`})
	if result.Status != "success" {
		t.Fatalf("expected success for uppercase action, got %s: %s", result.Status, result.Output)
	}
}

func TestLastRebootWithCount(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Action: "reboot", Count: 3})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	var entries []lastLoginEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}
	if len(entries) > 3 {
		t.Errorf("expected at most 3 entries, got %d", len(entries))
	}
}

func TestLastUnknownAction(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action": "invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %s", result.Status)
	}
}

func TestLastUnknownActionErrorMessage(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action": "bogus"}`})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "reboot") {
		t.Errorf("error message should mention reboot action: %s", result.Output)
	}
}

func TestLastInvalidJSON(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: "not valid json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Invalid parameters") {
		t.Errorf("expected 'Invalid parameters' in output, got: %s", result.Output)
	}
}

func TestLastLoginEntryJSON(t *testing.T) {
	entry := lastLoginEntry{
		User:      "gary",
		TTY:       "pts/0",
		From:      "192.168.1.1",
		LoginTime: "2025-01-15 10:30:00",
		Duration:  "01:25",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded lastLoginEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.User != "gary" || decoded.TTY != "pts/0" || decoded.From != "192.168.1.1" {
		t.Errorf("unexpected decoded values: %+v", decoded)
	}
}
