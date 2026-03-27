package commands

import (
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestEnvCommandName(t *testing.T) {
	cmd := &EnvCommand{}
	if cmd.Name() != "env" {
		t.Errorf("expected 'env', got %q", cmd.Name())
	}
}

func TestEnvListAll(t *testing.T) {
	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	// Should contain at least PATH
	if !strings.Contains(result.Output, "PATH=") {
		t.Error("env output should contain PATH")
	}
}

func TestEnvFilter(t *testing.T) {
	os.Setenv("FAWKES_TEST_VAR", "test_value")
	defer os.Unsetenv("FAWKES_TEST_VAR")

	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = "FAWKES_TEST"
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "FAWKES_TEST_VAR=test_value") {
		t.Errorf("output should contain filtered var, got %q", result.Output)
	}
}

func TestEnvFilterCaseInsensitive(t *testing.T) {
	os.Setenv("FAWKES_CASE_TEST", "val")
	defer os.Unsetenv("FAWKES_CASE_TEST")

	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = "fawkes_case"
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "FAWKES_CASE_TEST") {
		t.Error("filter should be case-insensitive")
	}
}

func TestEnvFilterNoMatch(t *testing.T) {
	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = "ZZZZNONEXISTENT999"
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "No environment variables") {
		t.Error("should report no matching vars")
	}
}

func TestEnvSorted(t *testing.T) {
	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = ""
	result := cmd.Execute(task)
	lines := strings.Split(result.Output, "\n")
	for i := 1; i < len(lines); i++ {
		if lines[i] < lines[i-1] {
			t.Error("env output should be sorted")
			break
		}
	}
}

// --- envGet tests ---

func TestEnvGetExisting(t *testing.T) {
	os.Setenv("FAWKES_GET_TEST", "hello123")
	defer os.Unsetenv("FAWKES_GET_TEST")

	result := envGet("FAWKES_GET_TEST")
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "FAWKES_GET_TEST=hello123") {
		t.Errorf("expected var=value, got %q", result.Output)
	}
}

func TestEnvGetNotSet(t *testing.T) {
	os.Unsetenv("FAWKES_NONEXIST_VAR")

	result := envGet("FAWKES_NONEXIST_VAR")
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "is not set") {
		t.Errorf("expected 'is not set' message, got %q", result.Output)
	}
}

func TestEnvGetEmptyName(t *testing.T) {
	result := envGet("")
	if result.Status != "error" {
		t.Errorf("expected error for empty name, got %q", result.Status)
	}
}

// --- envSet tests ---

func TestEnvSetNew(t *testing.T) {
	os.Unsetenv("FAWKES_SET_NEW")
	defer os.Unsetenv("FAWKES_SET_NEW")

	result := envSet("FAWKES_SET_NEW", "newval")
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Set FAWKES_SET_NEW=newval") {
		t.Errorf("expected 'Set' message, got %q", result.Output)
	}
	if val := os.Getenv("FAWKES_SET_NEW"); val != "newval" {
		t.Errorf("env var not actually set, got %q", val)
	}
}

func TestEnvSetUpdate(t *testing.T) {
	os.Setenv("FAWKES_SET_UPD", "oldval")
	defer os.Unsetenv("FAWKES_SET_UPD")

	result := envSet("FAWKES_SET_UPD", "newval")
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Updated") {
		t.Errorf("expected 'Updated' message, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "was: oldval") {
		t.Errorf("expected old value in message, got %q", result.Output)
	}
	if val := os.Getenv("FAWKES_SET_UPD"); val != "newval" {
		t.Errorf("env var not updated, got %q", val)
	}
}

func TestEnvSetEmptyName(t *testing.T) {
	result := envSet("", "val")
	if result.Status != "error" {
		t.Errorf("expected error for empty name, got %q", result.Status)
	}
}

// --- envUnset tests ---

func TestEnvUnsetExisting(t *testing.T) {
	os.Setenv("FAWKES_UNSET_TEST", "val")

	result := envUnset("FAWKES_UNSET_TEST")
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unset FAWKES_UNSET_TEST") {
		t.Errorf("expected 'Unset' message, got %q", result.Output)
	}
	if _, exists := os.LookupEnv("FAWKES_UNSET_TEST"); exists {
		t.Error("env var should no longer exist after unset")
	}
}

func TestEnvUnsetNotSet(t *testing.T) {
	os.Unsetenv("FAWKES_UNSET_NOPE")

	result := envUnset("FAWKES_UNSET_NOPE")
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "was not set") {
		t.Errorf("expected 'was not set' message, got %q", result.Output)
	}
}

func TestEnvUnsetEmptyName(t *testing.T) {
	result := envUnset("")
	if result.Status != "error" {
		t.Errorf("expected error for empty name, got %q", result.Status)
	}
}

// --- Execute routing via JSON ---

func TestEnvExecuteGetAction(t *testing.T) {
	os.Setenv("FAWKES_EXEC_GET", "testval")
	defer os.Unsetenv("FAWKES_EXEC_GET")

	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = `{"action":"get","name":"FAWKES_EXEC_GET"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "FAWKES_EXEC_GET=testval") {
		t.Errorf("expected var=value, got %q", result.Output)
	}
}

func TestEnvExecuteSetAction(t *testing.T) {
	os.Unsetenv("FAWKES_EXEC_SET")
	defer os.Unsetenv("FAWKES_EXEC_SET")

	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = `{"action":"set","name":"FAWKES_EXEC_SET","value":"abc"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if os.Getenv("FAWKES_EXEC_SET") != "abc" {
		t.Error("var should be set to 'abc'")
	}
}

func TestEnvExecuteUnsetAction(t *testing.T) {
	os.Setenv("FAWKES_EXEC_UNSET", "todelete")
	defer os.Unsetenv("FAWKES_EXEC_UNSET")

	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = `{"action":"unset","name":"FAWKES_EXEC_UNSET"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if _, exists := os.LookupEnv("FAWKES_EXEC_UNSET"); exists {
		t.Error("var should be unset")
	}
}

func TestEnvExecuteUnknownAction(t *testing.T) {
	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = `{"action":"delete"}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
}

func TestEnvExecuteListWithJSONFilter(t *testing.T) {
	os.Setenv("FAWKES_JSON_FILTER", "val")
	defer os.Unsetenv("FAWKES_JSON_FILTER")

	cmd := &EnvCommand{}
	task := structs.NewTask("t", "env", "")
	task.Params = `{"action":"list","filter":"FAWKES_JSON"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "FAWKES_JSON_FILTER") {
		t.Error("should contain filtered var")
	}
}
