//go:build darwin

package commands

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPersistEnumCommand_Name(t *testing.T) {
	cmd := &PersistEnumCommand{}
	if cmd.Name() != "persist-enum" {
		t.Errorf("expected 'persist-enum', got %q", cmd.Name())
	}
}

func TestPersistEnumCommand_Description(t *testing.T) {
	cmd := &PersistEnumCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Fatal("expected non-empty description")
	}
	if !strings.Contains(desc, "macOS") {
		t.Errorf("expected description to mention macOS, got: %s", desc)
	}
	if !strings.Contains(desc, "T1547") {
		t.Errorf("expected description to reference T1547, got: %s", desc)
	}
}

func TestPersistEnumCommand_ImplementsCommand(t *testing.T) {
	// Verify PersistEnumCommand has the expected methods at compile time.
	cmd := &PersistEnumCommand{}
	_ = cmd.Name()
	_ = cmd.Description()
}

func TestPersistEnumArgs_JSONParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"all category", `{"category":"all"}`, "all"},
		{"launchd category", `{"category":"launchd"}`, "launchd"},
		{"cron category", `{"category":"cron"}`, "cron"},
		{"shell category", `{"category":"shell"}`, "shell"},
		{"login category", `{"category":"login"}`, "login"},
		{"ssh category", `{"category":"ssh"}`, "ssh"},
		{"emond category", `{"category":"emond"}`, "emond"},
		{"at category", `{"category":"at"}`, "at"},
		{"empty object", `{}`, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var args persistEnumArgs
			if err := json.Unmarshal([]byte(tc.input), &args); err != nil {
				t.Fatalf("failed to unmarshal %q: %v", tc.input, err)
			}
			if args.Category != tc.expected {
				t.Errorf("expected Category=%q, got %q", tc.expected, args.Category)
			}
		})
	}
}

func TestPersistEnumArgs_JSONRoundTrip(t *testing.T) {
	original := persistEnumArgs{Category: "launchd"}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded persistEnumArgs
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Category != original.Category {
		t.Errorf("round-trip mismatch: expected %q, got %q", original.Category, decoded.Category)
	}
}

func TestPersistEnumArgs_JSONFieldName(t *testing.T) {
	// Verify the JSON field is "category" (lowercase), not "Category".
	args := persistEnumArgs{Category: "cron"}
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if !strings.Contains(string(data), `"category"`) {
		t.Errorf("expected JSON key 'category', got: %s", string(data))
	}
}

func TestPersistEnumArgs_DefaultZeroValue(t *testing.T) {
	var args persistEnumArgs
	if args.Category != "" {
		t.Errorf("expected zero-value Category to be empty, got %q", args.Category)
	}
}

func TestPersistEnumCommand_ZeroValueInit(t *testing.T) {
	// Verify the struct can be initialized as a zero value and methods still work.
	var cmd PersistEnumCommand
	if cmd.Name() != "persist-enum" {
		t.Errorf("zero-value Name() = %q, want 'persist-enum'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("zero-value Description() should not be empty")
	}
}
