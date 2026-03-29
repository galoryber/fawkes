//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestWdigestCommandName(t *testing.T) {
	assertCommandName(t, &WdigestCommand{}, "wdigest")
}

func TestWdigestCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &WdigestCommand{})
}

func TestWdigestEmptyParams(t *testing.T) {
	cmd := &WdigestCommand{}
	// Empty params defaults to "status"
	result := cmd.Execute(mockTask("wdigest", ""))
	assertSuccess(t, result)
	assertOutputContains(t, result, "WDigest")
}

func TestWdigestInvalidJSON(t *testing.T) {
	cmd := &WdigestCommand{}
	result := cmd.Execute(mockTask("wdigest", "not json"))
	assertError(t, result)
}

func TestWdigestUnknownAction(t *testing.T) {
	cmd := &WdigestCommand{}
	params, _ := json.Marshal(wdigestArgs{Action: "invalid"})
	result := cmd.Execute(mockTask("wdigest", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestWdigestStatusAction(t *testing.T) {
	cmd := &WdigestCommand{}
	params, _ := json.Marshal(wdigestArgs{Action: "status"})
	result := cmd.Execute(mockTask("wdigest", string(params)))
	assertSuccess(t, result)
	assertOutputContains(t, result, "WDigest Credential Caching")
}

func TestWdigestArgsUnmarshal(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		action string
	}{
		{"status", `{"action":"status"}`, "status"},
		{"enable", `{"action":"enable"}`, "enable"},
		{"disable", `{"action":"disable"}`, "disable"},
		{"empty", `{}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args wdigestArgs
			if err := json.Unmarshal([]byte(tt.json), &args); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if args.Action != tt.action {
				t.Errorf("Action = %q, want %q", args.Action, tt.action)
			}
		})
	}
}

func TestWdigestKeyPath(t *testing.T) {
	expected := `System\CurrentControlSet\Control\SecurityProviders\WDigest`
	if wdigestKeyPath != expected {
		t.Errorf("wdigestKeyPath = %q, want %q", wdigestKeyPath, expected)
	}
}
