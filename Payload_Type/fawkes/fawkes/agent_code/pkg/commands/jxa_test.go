//go:build darwin

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestJXACommand_Name(t *testing.T) {
	cmd := &JXACommand{}
	if cmd.Name() != "jxa" {
		t.Errorf("expected 'jxa', got %q", cmd.Name())
	}
}

func TestJXACommand_Description(t *testing.T) {
	cmd := &JXACommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "JXA") {
		t.Errorf("expected description to mention JXA, got: %s", desc)
	}
	if !strings.Contains(desc, "T1059.007") {
		t.Errorf("expected description to reference T1059.007, got: %s", desc)
	}
}

func TestJXACommand_EmptyParams(t *testing.T) {
	cmd := &JXACommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
	if !strings.Contains(result.Output, "must specify either -code") {
		t.Errorf("expected helpful error, got: %s", result.Output)
	}
}

func TestJXACommand_InvalidJSON(t *testing.T) {
	cmd := &JXACommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestJXACommand_BothCodeAndFile(t *testing.T) {
	cmd := &JXACommand{}
	params, _ := json.Marshal(jxaArgs{Code: "x", File: "/tmp/y.js"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when both code and file specified")
	}
	if !strings.Contains(result.Output, "not both") {
		t.Errorf("expected 'not both' error, got: %s", result.Output)
	}
}

func TestJXACommand_NonexistentFile(t *testing.T) {
	cmd := &JXACommand{}
	params, _ := json.Marshal(jxaArgs{File: "/nonexistent/path/script.js"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for nonexistent file")
	}
	if !strings.Contains(result.Output, "reading script file") {
		t.Errorf("expected file read error, got: %s", result.Output)
	}
}

func TestJXACommand_InlineCode(t *testing.T) {
	cmd := &JXACommand{}
	// Simple arithmetic that produces output
	params, _ := json.Marshal(jxaArgs{Code: "2 + 2"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "4") {
		t.Errorf("expected output to contain '4', got: %s", result.Output)
	}
}

func TestJXACommand_FileExecution(t *testing.T) {
	// Write a temp script file
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "test.js")
	if err := os.WriteFile(scriptPath, []byte("\"hello from file\""), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := &JXACommand{}
	params, _ := json.Marshal(jxaArgs{File: scriptPath})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "hello from file") {
		t.Errorf("expected output to contain 'hello from file', got: %s", result.Output)
	}
}

func TestJXACommand_SyntaxError(t *testing.T) {
	cmd := &JXACommand{}
	params, _ := json.Marshal(jxaArgs{Code: "this is not valid javascript {{{"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for syntax error")
	}
}

func TestJXACommand_SystemEventsAccess(t *testing.T) {
	cmd := &JXACommand{}
	// Get current user via JXA — doesn't require GUI access
	params, _ := json.Marshal(jxaArgs{Code: `ObjC.import("Foundation"); $.NSUserName().js`})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if result.Output == "" || result.Output == "Script executed successfully (no output)" {
		t.Error("expected username output")
	}
}

func TestJXACommand_ObjCBridge(t *testing.T) {
	cmd := &JXACommand{}
	// Use ObjC bridge to get home directory
	params, _ := json.Marshal(jxaArgs{Code: `ObjC.import("Foundation"); $.NSHomeDirectory().js`})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "/") {
		t.Errorf("expected path with '/', got: %s", result.Output)
	}
}

func TestJXACommand_Timeout(t *testing.T) {
	cmd := &JXACommand{}
	// Use a 1-second timeout with a sleep that would exceed it
	params, _ := json.Marshal(jxaArgs{Code: "delay(10)", Timeout: 1})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for timeout")
	}
	if !strings.Contains(result.Output, "timed out") {
		t.Errorf("expected timeout message, got: %s", result.Output)
	}
}

func TestJXACommand_DefaultTimeout(t *testing.T) {
	cmd := &JXACommand{}
	// Zero timeout should use default (60 seconds), should complete fast
	params, _ := json.Marshal(jxaArgs{Code: "1+1", Timeout: 0})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success with default timeout, got %s: %s", result.Status, result.Output)
	}
}
