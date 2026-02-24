package commands

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestDomainPolicyName(t *testing.T) {
	cmd := &DomainPolicyCommand{}
	if cmd.Name() != "domain-policy" {
		t.Errorf("expected 'domain-policy', got '%s'", cmd.Name())
	}
}

func TestDomainPolicyDescription(t *testing.T) {
	cmd := &DomainPolicyCommand{}
	if !strings.Contains(cmd.Description(), "T1201") {
		t.Error("description should contain MITRE technique T1201")
	}
}

func TestDomainPolicyEmptyParams(t *testing.T) {
	cmd := &DomainPolicyCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("empty params should return error")
	}
}

func TestDomainPolicyInvalidJSON(t *testing.T) {
	cmd := &DomainPolicyCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("invalid JSON should return error")
	}
}

func TestDomainPolicyMissingServer(t *testing.T) {
	cmd := &DomainPolicyCommand{}
	args := domainPolicyArgs{
		Action:   "all",
		Username: "user@domain",
		Password: "pass",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" || !strings.Contains(result.Output, "server") {
		t.Error("missing server should return error")
	}
}

func TestDomainPolicyUnknownAction(t *testing.T) {
	cmd := &DomainPolicyCommand{}
	args := domainPolicyArgs{
		Action:   "bogus",
		Server:   "192.0.2.1",
		Username: "user@domain",
		Password: "pass",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	// Will fail to connect (timeout) before reaching action check, but that's OK
	// The action validation happens after LDAP connection succeeds
	if result.Status != "error" {
		t.Error("unreachable server should return error")
	}
}

func TestDomainPolicyDefaultAction(t *testing.T) {
	cmd := &DomainPolicyCommand{}
	args := domainPolicyArgs{
		Server:   "192.0.2.1", // RFC 5737 - will timeout
		Username: "user@domain",
		Password: "pass",
	}
	data, _ := json.Marshal(args)
	result := cmd.Execute(structs.Task{Params: string(data)})
	// Should attempt "all" action (default), fail on connection
	if result.Status != "error" {
		t.Error("unreachable server should return error")
	}
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("empty action should default to 'all', not trigger unknown action")
	}
}

func TestFormatADInterval(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"empty", "", "(not set)"},
		{"zero", "0", "None"},
		{"1 hour negative", "-36000000000", "1h"},           // -36000000000 * 100ns = -1 hour
		{"30 minutes negative", "-18000000000", "30m"},      // -18000000000 * 100ns = -30 min
		{"1 day negative", "-864000000000", "1d"},            // -864000000000 * 100ns = -1 day
		{"42 days negative", "-36288000000000", "42d"},       // 42 days
		{"invalid", "abc", "abc"},                            // returns raw
		{"never expires", "-9223372036854775808", "Never"},   // max int64
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatADInterval(tt.input)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("formatADInterval(%q) = %q, want substring %q", tt.input, result, tt.contains)
			}
		})
	}
}

func TestParseADInterval(t *testing.T) {
	// 1 hour as 100-ns ticks (negative)
	d := parseADInterval("-36000000000")
	if d != 1*time.Hour {
		t.Errorf("expected 1h, got %v", d)
	}

	// 30 minutes
	d = parseADInterval("-18000000000")
	if d != 30*time.Minute {
		t.Errorf("expected 30m, got %v", d)
	}

	// Empty string
	d = parseADInterval("")
	if d != 0 {
		t.Errorf("expected 0, got %v", d)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		d        time.Duration
		expected string
	}{
		{"zero", 0, "None (0)"},
		{"30 minutes", 30 * time.Minute, "30m"},
		{"1 hour", time.Hour, "1h"},
		{"1 day 2 hours", 26 * time.Hour, "1d 2h"},
		{"42 days", 42 * 24 * time.Hour, "42d"},
		{"5 seconds", 5 * time.Second, "5s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.d)
			if result != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, result, tt.expected)
			}
		})
	}
}

func TestFormatPwdProperties(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"empty", "", "(not set)"},
		{"complexity", "1", "Complexity Required"},
		{"no complexity", "0", "No Complexity"},
		{"complexity + reversible", "3", "Complexity Required"},
		{"reversible check", "3", "Reversible Encryption"},
		{"invalid", "abc", "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatPwdProperties(tt.input)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("formatPwdProperties(%q) = %q, want substring %q", tt.input, result, tt.contains)
			}
		})
	}
}
