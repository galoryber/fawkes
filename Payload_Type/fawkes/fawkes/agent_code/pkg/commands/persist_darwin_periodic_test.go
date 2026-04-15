//go:build darwin

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPersistPeriodic_MissingPath(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"periodic","action":"install"}`})
	if result.Status != "error" {
		t.Errorf("Missing path should error, got status=%q", result.Status)
	}
}

func TestPersistPeriodic_InvalidSchedule(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"periodic","action":"install","path":"/tmp/test","schedule":"hourly"}`})
	if result.Status != "error" {
		t.Errorf("Invalid schedule should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "Invalid schedule") {
		t.Errorf("Error should mention invalid schedule, got %q", result.Output)
	}
}

func TestPersistPeriodic_InvalidAction(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"periodic","action":"bogus","path":"/tmp/test"}`})
	if result.Status != "error" {
		t.Errorf("Invalid action should error, got status=%q", result.Status)
	}
}

func TestPersistPeriodic_NamePrefixing(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"myagent", "500.myagent"},
		{"500.myagent", "500.myagent"},
		{"999.custom", "999.custom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := tt.name
			if !strings.HasPrefix(name, "5") && !strings.HasPrefix(name, "6") &&
				!strings.HasPrefix(name, "7") && !strings.HasPrefix(name, "8") &&
				!strings.HasPrefix(name, "9") {
				name = "500." + name
			}
			if name != tt.want {
				t.Errorf("name = %q, want %q", name, tt.want)
			}
		})
	}
}

func TestPersistFolderAction_MissingPath(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"folder-action","action":"install"}`})
	if result.Status != "error" {
		t.Errorf("Missing path should error, got status=%q", result.Status)
	}
}

func TestPersistFolderAction_InvalidAction(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"folder-action","action":"bogus","path":"/tmp/test"}`})
	if result.Status != "error" {
		t.Errorf("Invalid action should error, got status=%q", result.Status)
	}
}

func TestPersistArgs_MethodParsing(t *testing.T) {
	tests := []struct {
		input  string
		method string
	}{
		{`{"method":"periodic"}`, "periodic"},
		{`{"method":"folder-action"}`, "folder-action"},
		{`{"method":"periodic-script"}`, "periodic-script"},
		{`{"method":"folder-actions"}`, "folder-actions"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			var args persistArgs
			if err := json.Unmarshal([]byte(tt.input), &args); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if args.Method != tt.method {
				t.Errorf("Method = %q, want %q", args.Method, tt.method)
			}
		})
	}
}

func TestPersistFolderAction_RemoveNonexistent(t *testing.T) {
	result := persistFolderActionRemove(persistArgs{Name: "nonexistent_test_script"})
	if result.Status != "error" {
		t.Errorf("Removing nonexistent script should error, got status=%q", result.Status)
	}
}

func TestPersistPeriodic_RemoveNonexistent(t *testing.T) {
	result := persistPeriodicRemove(persistArgs{Name: "nonexistent_test_script"})
	// May error due to permissions or not found
	if result.Status == "success" {
		t.Error("Removing nonexistent script should not succeed")
	}
}

func TestPersistDarwin_UnknownMethod(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"bogus"}`})
	if result.Status != "error" {
		t.Errorf("Unknown method should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "periodic") {
		t.Errorf("Error should list periodic as valid method, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "folder-action") {
		t.Errorf("Error should list folder-action as valid method, got %q", result.Output)
	}
}
