//go:build linux
// +build linux

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func makeLolbinTask(action, path, args string) structs.Task {
	params, _ := json.Marshal(lolbinArgs{Action: action, Path: path, Args: args})
	return structs.Task{Params: string(params)}
}

func TestLolbinExecute_InvalidJSON(t *testing.T) {
	cmd := &LolbinCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Expected error for invalid JSON, got %s", result.Status)
	}
}

func TestLolbinExecute_EmptyAction(t *testing.T) {
	cmd := &LolbinCommand{}
	result := cmd.Execute(makeLolbinTask("", "", ""))
	if result.Status != "error" {
		t.Errorf("Expected error for empty action, got %s", result.Status)
	}
	if result.Output == "" {
		t.Error("Expected error message for empty action")
	}
}

func TestLolbinExecute_UnknownAction(t *testing.T) {
	cmd := &LolbinCommand{}
	result := cmd.Execute(makeLolbinTask("invalid_action", "", ""))
	if result.Status != "error" {
		t.Errorf("Expected error for unknown action, got %s", result.Status)
	}
	if result.Output == "" {
		t.Error("Expected error message listing valid actions")
	}
}

func TestLolbinExecute_AllValidActions(t *testing.T) {
	actions := []string{"python", "curl", "wget", "gcc", "perl", "ruby", "node", "awk", "lua"}
	cmd := &LolbinCommand{}
	for _, action := range actions {
		// Each action with empty params should either:
		// - Error with "not found" (binary missing)
		// - Error with input validation (missing required params)
		// - Succeed (unlikely with empty params)
		result := cmd.Execute(makeLolbinTask(action, "", ""))
		// Should not crash or panic
		if result.Output == "" && result.Status == "" {
			t.Errorf("Action %s returned empty result", action)
		}
	}
}

func TestFindBinary_ExistingBinary(t *testing.T) {
	// /bin/sh should exist on any Linux system
	result := findBinary("sh")
	if result == "" {
		t.Error("Expected to find 'sh' binary")
	}
}

func TestFindBinary_MultipleCandidates(t *testing.T) {
	// Should return first match
	result := findBinary("nonexistent_binary_xyz", "sh")
	if result == "" {
		t.Error("Expected to find 'sh' as fallback")
	}
}

func TestFindBinary_NoneExist(t *testing.T) {
	result := findBinary("nonexistent_binary_xyz", "also_nonexistent_abc")
	if result != "" {
		t.Errorf("Expected empty string for nonexistent binaries, got %s", result)
	}
}

func TestFindBinary_Empty(t *testing.T) {
	result := findBinary()
	if result != "" {
		t.Errorf("Expected empty string for no candidates, got %s", result)
	}
}

func TestGtfobinPython_NoInput(t *testing.T) {
	// Python with no code or args should fail validation
	result := gtfobinPython("", "")
	// Either "not found" or "provide code" error
	if result.Status != "error" {
		t.Errorf("Expected error for empty python input, got %s", result.Status)
	}
}

func TestGtfobinCurl_NoURL(t *testing.T) {
	result := gtfobinCurl("", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty curl URL, got %s", result.Status)
	}
}

func TestGtfobinWget_NoURL(t *testing.T) {
	result := gtfobinWget("", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty wget URL, got %s", result.Status)
	}
}

func TestGtfobinGCC_NoCode(t *testing.T) {
	result := gtfobinGCC("", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty gcc code, got %s", result.Status)
	}
}

func TestGtfobinPerl_NoInput(t *testing.T) {
	result := gtfobinPerl("", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty perl input, got %s", result.Status)
	}
}

func TestGtfobinRuby_NoInput(t *testing.T) {
	result := gtfobinRuby("", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty ruby input, got %s", result.Status)
	}
}

func TestGtfobinNode_NoInput(t *testing.T) {
	result := gtfobinNode("", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty node input, got %s", result.Status)
	}
}

func TestGtfobinAwk_NoProgram(t *testing.T) {
	result := gtfobinAwk("", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty awk program, got %s", result.Status)
	}
}

