//go:build !windows

package commands

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCredHarvestName(t *testing.T) {
	cmd := &CredHarvestCommand{}
	if cmd.Name() != "cred-harvest" {
		t.Errorf("expected 'cred-harvest', got '%s'", cmd.Name())
	}
}

func TestCredHarvestDescription(t *testing.T) {
	cmd := &CredHarvestCommand{}
	if !strings.Contains(cmd.Description(), "credential") {
		t.Errorf("description should mention credentials: %s", cmd.Description())
	}
}

func TestCredHarvestEmptyParams(t *testing.T) {
	cmd := &CredHarvestCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %s", result.Status)
	}
}

func TestCredHarvestBadJSON(t *testing.T) {
	cmd := &CredHarvestCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %s", result.Status)
	}
}

func TestCredHarvestInvalidAction(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got: %s", result.Output)
	}
}

func TestCredHarvestShadow(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "shadow"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for shadow, got %s: %s", result.Status, result.Output)
	}
	// Should mention shadow file (even if permission denied)
	if !strings.Contains(result.Output, "shadow") {
		t.Errorf("shadow output should mention shadow: %s", result.Output)
	}
	// Should show passwd accounts
	if !strings.Contains(result.Output, "/etc/passwd") {
		t.Errorf("shadow output should mention /etc/passwd: %s", result.Output)
	}
}

func TestCredHarvestCloud(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "cloud"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for cloud, got %s: %s", result.Status, result.Output)
	}
	// Should check for AWS, GCP, Azure, etc.
	if !strings.Contains(result.Output, "AWS") {
		t.Errorf("cloud output should mention AWS: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Kubernetes") {
		t.Errorf("cloud output should mention Kubernetes: %s", result.Output)
	}
}

func TestCredHarvestConfigs(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "configs"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for configs, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Application Credentials") {
		t.Errorf("configs output should contain header: %s", result.Output)
	}
}

func TestCredHarvestAll(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "all"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for all, got %s: %s", result.Status, result.Output)
	}
	// Should contain sections from all three actions
	if !strings.Contains(result.Output, "System Credential") {
		t.Errorf("all output should contain shadow section: %s", result.Output[:200])
	}
	if !strings.Contains(result.Output, "Cloud") {
		t.Errorf("all output should contain cloud section: %s", result.Output[:200])
	}
	if !strings.Contains(result.Output, "Application") {
		t.Errorf("all output should contain configs section: %s", result.Output[:200])
	}
}

func TestCredHarvestUserFilter(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "shadow", "user": "root"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for filtered shadow, got %s: %s", result.Status, result.Output)
	}
}

func TestGetUserHomes(t *testing.T) {
	homes := getUserHomes("")
	if len(homes) == 0 {
		t.Skip("no user homes found (might be in container)")
	}
	// At least one home directory should exist
	for _, home := range homes {
		if _, err := os.Stat(home); err != nil {
			t.Errorf("home directory %s doesn't exist", home)
		}
	}
}

func TestGetUserHomesFiltered(t *testing.T) {
	homes := getUserHomes("root")
	// Root home should either be found or not (depends on system)
	for _, home := range homes {
		if !strings.Contains(home, "root") {
			t.Errorf("expected root home, got %s", home)
		}
	}
}

func TestIndentLines(t *testing.T) {
	result := indentLines("line1\nline2\nline3", "  ")
	expected := "  line1\n  line2\n  line3"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestIndentLinesEmpty(t *testing.T) {
	result := indentLines("line1\n\nline3", "  ")
	if !strings.Contains(result, "  line1") || !strings.Contains(result, "  line3") {
		t.Errorf("non-empty lines should be indented: %q", result)
	}
}
