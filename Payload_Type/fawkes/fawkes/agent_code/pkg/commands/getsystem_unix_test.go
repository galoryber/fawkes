//go:build linux || darwin
// +build linux darwin

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestGetsystemUnix_Name(t *testing.T) {
	cmd := &GetSystemCommand{}
	if cmd.Name() != "getsystem" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "getsystem")
	}
}

func TestGetsystemUnix_Description(t *testing.T) {
	cmd := &GetSystemCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestGetsystemUnix_InvalidJSON(t *testing.T) {
	cmd := &GetSystemCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%s", result.Status)
	}
}

func TestGetsystemUnix_UnknownTechnique(t *testing.T) {
	cmd := &GetSystemCommand{}
	args := getSystemArgs{Technique: "nonexistent"}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Unknown technique should error, got status=%s", result.Status)
	}
}

func TestGetsystemUnix_CheckReturnsJSON(t *testing.T) {
	cmd := &GetSystemCommand{}
	args := getSystemArgs{Technique: "check"}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Errorf("check should succeed, got status=%s output=%s", result.Status, result.Output)
	}

	// Parse the output as JSON
	var output map[string]interface{}
	if err := json.Unmarshal([]byte(result.Output), &output); err != nil {
		t.Errorf("check output should be valid JSON: %v", err)
	}
	if _, ok := output["vectors"]; !ok {
		t.Error("check output should contain 'vectors' field")
	}
	if _, ok := output["uid"]; !ok {
		t.Error("check output should contain 'uid' field")
	}
}

func TestGetsystemUnix_EmptyParamsDefaultsToCheck(t *testing.T) {
	cmd := &GetSystemCommand{}
	task := structs.Task{Params: "{}"}
	result := cmd.Execute(task)
	// Should succeed (defaults to check technique)
	if result.Status != "success" {
		t.Errorf("Empty params should default to check, got status=%s", result.Status)
	}
}


