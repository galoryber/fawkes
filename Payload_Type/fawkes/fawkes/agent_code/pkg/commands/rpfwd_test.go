package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestRpfwdName(t *testing.T) {
	cmd := &RpfwdCommand{}
	if cmd.Name() != "rpfwd" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "rpfwd")
	}
}

func TestRpfwdDescription(t *testing.T) {
	cmd := &RpfwdCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
	if !strings.Contains(desc, "reverse port forward") {
		t.Errorf("Description() = %q, should mention reverse port forward", desc)
	}
}

func TestRpfwdInvalidJSON(t *testing.T) {
	cmd := &RpfwdCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("invalid JSON should return error")
	}
	if !strings.Contains(result.Output, "Failed to parse") {
		t.Errorf("expected parse error, got: %s", result.Output)
	}
}

func TestRpfwdNilManager(t *testing.T) {
	// Save and restore
	orig := rpfwdManagerInstance
	rpfwdManagerInstance = nil
	defer func() { rpfwdManagerInstance = orig }()

	cmd := &RpfwdCommand{}
	params, _ := json.Marshal(map[string]interface{}{
		"action": "start",
		"port":   8080,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("nil manager should return error")
	}
	if !strings.Contains(result.Output, "not initialized") {
		t.Errorf("expected not initialized error, got: %s", result.Output)
	}
}

func TestRpfwdUnknownAction(t *testing.T) {
	// Save and restore
	orig := rpfwdManagerInstance
	rpfwdManagerInstance = nil
	defer func() { rpfwdManagerInstance = orig }()

	cmd := &RpfwdCommand{}
	// Unknown action should fail on manager check before reaching switch
	// But if manager were non-nil, it would hit the default case
	params, _ := json.Marshal(map[string]interface{}{
		"action": "restart",
		"port":   8080,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// With nil manager, we get manager error first
	if result.Status != "error" {
		t.Error("should return error")
	}
}

func TestSetGetRpfwdManager(t *testing.T) {
	// Save and restore
	orig := rpfwdManagerInstance
	defer func() { rpfwdManagerInstance = orig }()

	SetRpfwdManager(nil)
	if GetRpfwdManager() != nil {
		t.Error("expected nil manager after SetRpfwdManager(nil)")
	}
}
