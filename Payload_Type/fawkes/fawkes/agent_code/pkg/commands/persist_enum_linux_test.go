//go:build linux

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPersistEnumCommand_Metadata(t *testing.T) {
	cmd := &PersistEnumCommand{}
	if cmd.Name() != "persist-enum" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "persist-enum")
	}
	if cmd.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestPersistEnumCommand_DefaultAll(t *testing.T) {
	cmd := &PersistEnumCommand{}
	result := cmd.Execute(structs.Task{Params: `{}`})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Persistence Enumeration (Linux)") {
		t.Error("output missing Linux header")
	}
	if !strings.Contains(result.Output, "Cron Jobs") {
		t.Error("output missing Cron section")
	}
	if !strings.Contains(result.Output, "Systemd Units") {
		t.Error("output missing Systemd section")
	}
	if !strings.Contains(result.Output, "Shell Profiles") {
		t.Error("output missing Shell Profiles section")
	}
	if !strings.Contains(result.Output, "Startup / Init") {
		t.Error("output missing Startup section")
	}
	if !strings.Contains(result.Output, "SSH Authorized Keys") {
		t.Error("output missing SSH section")
	}
	if !strings.Contains(result.Output, "LD_PRELOAD") {
		t.Error("output missing Preload section")
	}
	if !strings.Contains(result.Output, "Total:") {
		t.Error("output missing total count")
	}
}

func TestPersistEnumCommand_CategoryFilter(t *testing.T) {
	cmd := &PersistEnumCommand{}

	// Test single category
	params, _ := json.Marshal(persistEnumArgs{Category: "cron"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Cron Jobs") {
		t.Error("output missing Cron section")
	}
	// Should NOT have other sections
	if strings.Contains(result.Output, "Systemd Units") {
		t.Error("output should not contain Systemd section when category=cron")
	}
}

func TestPersistEnumCommand_SystemdCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "systemd"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Systemd Units") {
		t.Error("output missing Systemd section")
	}
}

func TestPersistEnumCommand_ShellCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "shell"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Shell Profiles") {
		t.Error("output missing Shell Profiles section")
	}
}

func TestPersistEnumCommand_PreloadCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "preload"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "LD_PRELOAD") {
		t.Error("output missing Preload section")
	}
}

func TestPersistEnumCommand_InvalidJSON(t *testing.T) {
	cmd := &PersistEnumCommand{}
	result := cmd.Execute(structs.Task{Params: `{bad`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestPersistEnumCommand_EmptyParams(t *testing.T) {
	cmd := &PersistEnumCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Fatalf("expected success for empty params, got %q: %s", result.Status, result.Output)
	}
	// Should default to "all"
	if !strings.Contains(result.Output, "Cron Jobs") {
		t.Error("empty params should default to all categories")
	}
}

func TestCurrentHomeDir(t *testing.T) {
	home := currentHomeDir()
	if home == "" {
		t.Error("currentHomeDir() returned empty string")
	}
}

func TestPersistEnumArgs_Unmarshal(t *testing.T) {
	input := `{"category": "cron"}`
	var args persistEnumArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Category != "cron" {
		t.Errorf("Category = %q, want %q", args.Category, "cron")
	}
}
