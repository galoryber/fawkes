package commands

import (
	"encoding/json"
	"testing"
)

func TestFirewallArgsUnmarshal(t *testing.T) {
	input := `{"action":"list","name":"test-rule","direction":"in","protocol":"tcp","port":"443"}`
	var args firewallArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if args.Action != "list" {
		t.Errorf("Expected action 'list', got '%s'", args.Action)
	}
	if args.Name != "test-rule" {
		t.Errorf("Expected name 'test-rule', got '%s'", args.Name)
	}
	if args.Direction != "in" {
		t.Errorf("Expected direction 'in', got '%s'", args.Direction)
	}
	if args.Protocol != "tcp" {
		t.Errorf("Expected protocol 'tcp', got '%s'", args.Protocol)
	}
	if args.Port != "443" {
		t.Errorf("Expected port '443', got '%s'", args.Port)
	}
}
