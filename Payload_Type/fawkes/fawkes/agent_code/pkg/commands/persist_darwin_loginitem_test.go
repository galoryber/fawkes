//go:build darwin

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPersistLoginItem_MissingPath(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"login-item","action":"install"}`})
	if result.Status != "error" {
		t.Errorf("Missing path should error, got status=%q", result.Status)
	}
}

func TestPersistLoginItem_InvalidAction(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"login-item","action":"bogus","path":"/tmp/test"}`})
	if result.Status != "error" {
		t.Errorf("Invalid action should error, got status=%q", result.Status)
	}
}

func TestPersistLoginItem_MethodAliases(t *testing.T) {
	aliases := []string{"login-item", "login-items", "loginitem"}
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			cmd := &PersistCommand{}
			result := cmd.Execute(structs.Task{Params: `{"method":"` + alias + `","action":"install"}`})
			if result.Status != "error" {
				t.Errorf("Missing path should error for alias %q, got status=%q", alias, result.Status)
			}
			if strings.Contains(result.Output, "Unknown method") {
				t.Errorf("Alias %q should be recognized, got %q", alias, result.Output)
			}
		})
	}
}

func TestPersistAuthPlugin_MissingPath(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"auth-plugin","action":"install"}`})
	if result.Status != "error" {
		t.Errorf("Missing path should error, got status=%q", result.Status)
	}
}

func TestPersistAuthPlugin_RequiresRoot(t *testing.T) {
	result := persistAuthPluginInstall(persistArgs{Path: "/tmp/agent", Name: "TestAuth"})
	// Non-root should fail with root requirement
	if result.Status == "success" {
		t.Error("Non-root install should not succeed")
	}
}

func TestPersistAuthPlugin_RemoveRequiresRoot(t *testing.T) {
	result := persistAuthPluginRemove(persistArgs{Name: "NonexistentAuth"})
	if result.Status == "success" {
		t.Error("Non-root remove should not succeed")
	}
}

func TestPersistAuthPlugin_InvalidAction(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"auth-plugin","action":"bogus","path":"/tmp/test"}`})
	if result.Status != "error" {
		t.Errorf("Invalid action should error, got status=%q", result.Status)
	}
}

func TestPersistAuthPlugin_MethodAliases(t *testing.T) {
	aliases := []string{"auth-plugin", "authorization-plugin", "authplugin"}
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			cmd := &PersistCommand{}
			result := cmd.Execute(structs.Task{Params: `{"method":"` + alias + `","action":"install"}`})
			if result.Status != "error" {
				t.Errorf("Missing path should error for alias %q, got status=%q", alias, result.Status)
			}
			if strings.Contains(result.Output, "Unknown method") {
				t.Errorf("Alias %q should be recognized, got %q", alias, result.Output)
			}
		})
	}
}

func TestPersistLoginItem_RemoveDefaultName(t *testing.T) {
	result := persistLoginItemRemove(persistArgs{})
	// Will fail since no login item exists, but should not panic
	if result.Status == "" {
		t.Error("Remove should return a status")
	}
}

func TestPersistArgs_NewMethodParsing(t *testing.T) {
	tests := []struct {
		input  string
		method string
	}{
		{`{"method":"login-item"}`, "login-item"},
		{`{"method":"auth-plugin"}`, "auth-plugin"},
		{`{"method":"authorization-plugin"}`, "authorization-plugin"},
		{`{"method":"loginitem"}`, "loginitem"},
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

func TestPersistDarwin_ErrorListsNewMethods(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"method":"bogus"}`})
	if result.Status != "error" {
		t.Errorf("Unknown method should error, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "login-item") {
		t.Errorf("Error should list login-item as valid method, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "auth-plugin") {
		t.Errorf("Error should list auth-plugin as valid method, got %q", result.Output)
	}
}
