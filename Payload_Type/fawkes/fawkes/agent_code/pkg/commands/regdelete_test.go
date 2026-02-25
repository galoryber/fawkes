//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

func TestRegDeleteNameAndDescription(t *testing.T) {
	cmd := &RegDeleteCommand{}
	if cmd.Name() != "reg-delete" {
		t.Errorf("Expected name 'reg-delete', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestRegDeleteEmptyParams(t *testing.T) {
	cmd := &RegDeleteCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("Expected parameters required error, got: %s", result.Output)
	}
}

func TestRegDeleteInvalidJSON(t *testing.T) {
	cmd := &RegDeleteCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestRegDeleteMissingPath(t *testing.T) {
	cmd := &RegDeleteCommand{}
	params, _ := json.Marshal(map[string]string{"hive": "HKCU"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing path")
	}
	if !strings.Contains(result.Output, "path is required") {
		t.Errorf("Expected path required error, got: %s", result.Output)
	}
}

func TestRegDeleteInvalidHive(t *testing.T) {
	cmd := &RegDeleteCommand{}
	params, _ := json.Marshal(map[string]string{
		"hive": "INVALID",
		"path": "Software\\Test",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid hive")
	}
	if !strings.Contains(result.Output, "unsupported registry hive") {
		t.Errorf("Expected hive error, got: %s", result.Output)
	}
}

func TestRegDeleteValueLifecycle(t *testing.T) {
	// Create a test key and value, then delete the value
	testPath := `Software\FawkesTest\RegDeleteTest`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE|registry.READ)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	err = key.SetStringValue("TestVal", "hello")
	key.Close()
	if err != nil {
		t.Fatalf("Failed to set test value: %v", err)
	}

	// Delete the value
	cmd := &RegDeleteCommand{}
	params, _ := json.Marshal(map[string]string{
		"hive": "HKCU",
		"path": testPath,
		"name": "TestVal",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Deleted value") {
		t.Errorf("Expected delete confirmation, got: %s", result.Output)
	}

	// Verify value is gone
	key, err = registry.OpenKey(registry.CURRENT_USER, testPath, registry.READ)
	if err != nil {
		t.Fatalf("Failed to reopen test key: %v", err)
	}
	_, _, err = key.GetStringValue("TestVal")
	key.Close()
	if err == nil {
		t.Error("Value should have been deleted")
	}

	// Cleanup: delete the test keys
	registry.DeleteKey(registry.CURRENT_USER, testPath)
	registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
}

func TestRegDeleteKeyLifecycle(t *testing.T) {
	// Create a test key, then delete it
	testPath := `Software\FawkesTest\RegDeleteKeyTest`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testPath, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
	key.Close()

	// Delete the key (non-recursive)
	cmd := &RegDeleteCommand{}
	params, _ := json.Marshal(map[string]string{
		"hive": "HKCU",
		"path": testPath,
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Deleted key") {
		t.Errorf("Expected delete confirmation, got: %s", result.Output)
	}

	// Verify key is gone
	_, err = registry.OpenKey(registry.CURRENT_USER, testPath, registry.READ)
	if err == nil {
		t.Error("Key should have been deleted")
	}

	// Cleanup
	registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
}

func TestRegDeleteKeyRecursive(t *testing.T) {
	// Create a key tree: parent/child1, parent/child2
	parentPath := `Software\FawkesTest\RecursiveTest`
	child1Path := parentPath + `\Child1`
	child2Path := parentPath + `\Child2`

	for _, p := range []string{child1Path, child2Path} {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, p, registry.SET_VALUE)
		if err != nil {
			t.Fatalf("Failed to create %s: %v", p, err)
		}
		key.Close()
	}

	// Non-recursive should fail (has subkeys)
	cmd := &RegDeleteCommand{}
	params, _ := json.Marshal(map[string]string{
		"hive": "HKCU",
		"path": parentPath,
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for non-recursive delete of key with subkeys")
	}

	// Recursive should succeed
	params, _ = json.Marshal(map[string]string{
		"hive":      "HKCU",
		"path":      parentPath,
		"recursive": "true",
	})
	task = structs.Task{Params: string(params)}
	result = cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success for recursive delete, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "3 keys removed") {
		t.Errorf("Expected 3 keys removed, got: %s", result.Output)
	}

	// Verify all gone
	_, err := registry.OpenKey(registry.CURRENT_USER, parentPath, registry.READ)
	if err == nil {
		t.Error("Parent key should have been deleted")
	}

	// Cleanup
	registry.DeleteKey(registry.CURRENT_USER, `Software\FawkesTest`)
}

func TestRegDeleteNonexistentValue(t *testing.T) {
	cmd := &RegDeleteCommand{}
	params, _ := json.Marshal(map[string]string{
		"hive": "HKCU",
		"path": "Software",
		"name": "NonexistentValue12345",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for nonexistent value")
	}
}

func TestRegDeleteNonexistentKey(t *testing.T) {
	cmd := &RegDeleteCommand{}
	params, _ := json.Marshal(map[string]string{
		"hive": "HKCU",
		"path": `Software\NonexistentKey12345\DoesNotExist`,
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for nonexistent key")
	}
}
