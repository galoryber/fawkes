package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSocksCommandName(t *testing.T) {
	cmd := &SocksCommand{}
	if cmd.Name() != "socks" {
		t.Errorf("expected 'socks', got '%s'", cmd.Name())
	}
}

func TestSocksCommandDescription(t *testing.T) {
	cmd := &SocksCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestSocksStart(t *testing.T) {
	cmd := &SocksCommand{}
	params, _ := json.Marshal(struct {
		Action string `json:"action"`
		Port   int    `json:"port"`
	}{Action: "start", Port: 1080})

	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "completed" {
		t.Errorf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("should be completed")
	}
	if !strings.Contains(result.Output, "1080") {
		t.Errorf("output should mention port 1080: %s", result.Output)
	}
	if !strings.Contains(result.Output, "SOCKS5") {
		t.Errorf("output should mention SOCKS5: %s", result.Output)
	}
}

func TestSocksStop(t *testing.T) {
	cmd := &SocksCommand{}
	params, _ := json.Marshal(struct {
		Action string `json:"action"`
		Port   int    `json:"port"`
	}{Action: "stop", Port: 1080})

	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "completed" {
		t.Errorf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "stopped") {
		t.Errorf("output should mention stopped: %s", result.Output)
	}
}

func TestSocksUnknownAction(t *testing.T) {
	cmd := &SocksCommand{}
	params, _ := json.Marshal(struct {
		Action string `json:"action"`
		Port   int    `json:"port"`
	}{Action: "restart", Port: 1080})

	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "restart") {
		t.Errorf("error should mention the invalid action: %s", result.Output)
	}
}

func TestSocksInvalidJSON(t *testing.T) {
	cmd := &SocksCommand{}
	result := cmd.Execute(structs.Task{Params: "not-json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %s", result.Status)
	}
}

func TestSocksEmptyParams(t *testing.T) {
	cmd := &SocksCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %s", result.Status)
	}
}
