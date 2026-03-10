//go:build darwin

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestGetPrivsCommand_Name(t *testing.T) {
	cmd := &GetPrivsCommand{}
	if cmd.Name() != "getprivs" {
		t.Errorf("Expected 'getprivs', got '%s'", cmd.Name())
	}
}

func TestGetPrivsCommand_Description(t *testing.T) {
	cmd := &GetPrivsCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestGetPrivsCommand_ListAction(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}

	var output privsOutput
	if err := json.Unmarshal([]byte(result.Output), &output); err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	if output.Identity == "" {
		t.Error("Identity should not be empty")
	}
}

func TestGetPrivsCommand_EmptyParams(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("Expected success with empty params, got %s", result.Status)
	}
}

func TestGetPrivsCommand_UnsupportedActions(t *testing.T) {
	cmd := &GetPrivsCommand{}
	for _, action := range []string{"enable", "disable", "strip"} {
		result := cmd.Execute(structs.Task{Params: `{"action":"` + action + `"}`})
		if result.Status != "error" {
			t.Errorf("Action '%s' should return error on macOS, got %s", action, result.Status)
		}
	}
}

func TestGetPrivsCommand_UnknownAction(t *testing.T) {
	cmd := &GetPrivsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"bogus"}`})
	if result.Status != "error" {
		t.Errorf("Expected error for unknown action, got %s", result.Status)
	}
}

func TestParseEntitlementKeys(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
	<key>com.apple.security.app-sandbox</key>
	<true/>
	<key>com.apple.security.network.client</key>
	<true/>
	<key>com.apple.security.files.downloads.read-only</key>
	<false/>
</dict>
</plist>`

	keys := parseEntitlementKeys(xmlData)
	if len(keys) != 2 {
		t.Fatalf("Expected 2 granted entitlements, got %d: %v", len(keys), keys)
	}
	if keys[0] != "com.apple.security.app-sandbox" {
		t.Errorf("Expected app-sandbox, got '%s'", keys[0])
	}
	if keys[1] != "com.apple.security.network.client" {
		t.Errorf("Expected network.client, got '%s'", keys[1])
	}
}

func TestParseEntitlementKeys_Empty(t *testing.T) {
	keys := parseEntitlementKeys("")
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys for empty input, got %d", len(keys))
	}
}
