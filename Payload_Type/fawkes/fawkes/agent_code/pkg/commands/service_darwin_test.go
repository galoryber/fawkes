//go:build darwin

package commands

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestServiceCommand_Name(t *testing.T) {
	cmd := &ServiceCommand{}
	if cmd.Name() != "service" {
		t.Errorf("expected 'service', got %q", cmd.Name())
	}
}

func TestServiceCommand_Description(t *testing.T) {
	cmd := &ServiceCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("description should not be empty")
	}
	if !strings.Contains(desc, "launchctl") {
		t.Errorf("expected description to mention launchctl, got: %s", desc)
	}
}

func TestServiceArgs_JSONParsing_AllFields(t *testing.T) {
	input := `{
		"action":  "create",
		"name":    "com.example.test",
		"binpath": "/usr/local/bin/test",
		"display": "Test Service",
		"start":   "auto"
	}`

	var args serviceArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("failed to unmarshal serviceArgs: %v", err)
	}

	if args.Action != "create" {
		t.Errorf("Action: expected 'create', got %q", args.Action)
	}
	if args.Name != "com.example.test" {
		t.Errorf("Name: expected 'com.example.test', got %q", args.Name)
	}
	if args.BinPath != "/usr/local/bin/test" {
		t.Errorf("BinPath: expected '/usr/local/bin/test', got %q", args.BinPath)
	}
	if args.Display != "Test Service" {
		t.Errorf("Display: expected 'Test Service', got %q", args.Display)
	}
	if args.Start != "auto" {
		t.Errorf("Start: expected 'auto', got %q", args.Start)
	}
}

func TestServiceArgs_JSONParsing_MinimalFields(t *testing.T) {
	input := `{"action": "list"}`

	var args serviceArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("failed to unmarshal serviceArgs: %v", err)
	}

	if args.Action != "list" {
		t.Errorf("Action: expected 'list', got %q", args.Action)
	}
	if args.Name != "" {
		t.Errorf("Name: expected empty string, got %q", args.Name)
	}
	if args.BinPath != "" {
		t.Errorf("BinPath: expected empty string, got %q", args.BinPath)
	}
	if args.Display != "" {
		t.Errorf("Display: expected empty string, got %q", args.Display)
	}
	if args.Start != "" {
		t.Errorf("Start: expected empty string, got %q", args.Start)
	}
}

func TestServiceArgs_ActionValues(t *testing.T) {
	actions := []string{
		"list", "query", "start", "stop", "restart",
		"create", "delete", "enable", "disable",
	}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			input, err := json.Marshal(serviceArgs{Action: action})
			if err != nil {
				t.Fatalf("failed to marshal serviceArgs: %v", err)
			}

			var parsed serviceArgs
			if err := json.Unmarshal(input, &parsed); err != nil {
				t.Fatalf("failed to unmarshal serviceArgs: %v", err)
			}

			if parsed.Action != action {
				t.Errorf("expected action %q, got %q", action, parsed.Action)
			}
		})
	}
}

func TestServiceArgs_JSONRoundTrip(t *testing.T) {
	original := serviceArgs{
		Action:  "create",
		Name:    "com.globetech.fawkes",
		BinPath: "/opt/fawkes/bin/agent",
		Display: "Fawkes Agent",
		Start:   "disabled",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded serviceArgs
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded != original {
		t.Errorf("round-trip mismatch:\n  original: %+v\n  decoded:  %+v", original, decoded)
	}
}

func TestServiceArgs_JSONTags(t *testing.T) {
	args := serviceArgs{
		Action:  "query",
		Name:    "com.test.svc",
		BinPath: "/bin/test",
		Display: "Test",
		Start:   "auto",
	}

	data, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	raw := string(data)

	// Verify JSON keys match the struct tags
	expectedKeys := []string{`"action"`, `"name"`, `"binpath"`, `"display"`, `"start"`}
	for _, key := range expectedKeys {
		if !strings.Contains(raw, key) {
			t.Errorf("expected JSON to contain key %s, got: %s", key, raw)
		}
	}
}

func TestServiceArgs_UnknownFieldsIgnored(t *testing.T) {
	input := `{"action": "list", "unknown_field": "should be ignored", "extra": 42}`

	var args serviceArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("unknown fields should be silently ignored, got error: %v", err)
	}

	if args.Action != "list" {
		t.Errorf("Action: expected 'list', got %q", args.Action)
	}
}
