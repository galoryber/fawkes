package commands

import (
	"encoding/json"
	"testing"
)

func TestGetPrivsParamsUnmarshal(t *testing.T) {
	input := `{"action":"list","privilege":"SeDebugPrivilege"}`
	var params getPrivsParams
	if err := json.Unmarshal([]byte(input), &params); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if params.Action != "list" {
		t.Errorf("Expected action 'list', got '%s'", params.Action)
	}
	if params.Privilege != "SeDebugPrivilege" {
		t.Errorf("Expected privilege 'SeDebugPrivilege', got '%s'", params.Privilege)
	}
}

func TestGetPrivsParamsDefaults(t *testing.T) {
	var params getPrivsParams
	if err := json.Unmarshal([]byte(`{}`), &params); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if params.Action != "" {
		t.Errorf("Expected empty action, got '%s'", params.Action)
	}
}

func TestPrivsOutputMarshal(t *testing.T) {
	output := privsOutput{
		Identity:  "testuser (uid=1000)",
		Source:    "process",
		Integrity: "Standard",
		Privileges: []privOutputEntry{
			{Name: "CAP_SYS_ADMIN", Status: "Enabled", Description: "System administration"},
		},
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded privsOutput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Identity != output.Identity {
		t.Errorf("Identity mismatch: got '%s'", decoded.Identity)
	}
	if len(decoded.Privileges) != 1 {
		t.Fatalf("Expected 1 privilege, got %d", len(decoded.Privileges))
	}
	if decoded.Privileges[0].Name != "CAP_SYS_ADMIN" {
		t.Errorf("Expected CAP_SYS_ADMIN, got '%s'", decoded.Privileges[0].Name)
	}
}
