package commands

import (
	"encoding/json"
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

