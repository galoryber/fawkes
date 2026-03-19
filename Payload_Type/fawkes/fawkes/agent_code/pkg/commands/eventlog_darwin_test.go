//go:build darwin

package commands

import (
	"strings"
	"testing"
)

func TestExtractSubsystems(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
		{
			name:     "no subsystem field",
			input:    `{"timestamp":"2024-01-01","process":"sshd","message":"test"}`,
			expected: nil,
		},
		{
			name:  "single subsystem",
			input: `{"timestamp":"2024-01-01","subsystem":"com.apple.xpc","message":"test"}`,
			expected: []string{"com.apple.xpc"},
		},
		{
			name: "multiple unique subsystems",
			input: `{"subsystem":"com.apple.xpc","message":"a"}
{"subsystem":"com.apple.authd","message":"b"}
{"subsystem":"com.apple.network","message":"c"}`,
			expected: []string{"com.apple.xpc", "com.apple.authd", "com.apple.network"},
		},
		{
			name: "deduplicate subsystems",
			input: `{"subsystem":"com.apple.xpc","message":"a"}
{"subsystem":"com.apple.xpc","message":"b"}
{"subsystem":"com.apple.authd","message":"c"}`,
			expected: []string{"com.apple.xpc", "com.apple.authd"},
		},
		{
			name:     "empty subsystem value",
			input:    `{"subsystem":"","message":"test"}`,
			expected: nil,
		},
		{
			name: "mixed with and without subsystem",
			input: `{"process":"kernel","message":"boot"}
{"subsystem":"com.apple.launchd","message":"start"}
{"process":"sshd","message":"auth"}`,
			expected: []string{"com.apple.launchd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSubsystems(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("extractSubsystems() returned %d subsystems, want %d\ngot:  %v\nwant: %v",
					len(result), len(tt.expected), result, tt.expected)
				return
			}
			for i, s := range result {
				if s != tt.expected[i] {
					t.Errorf("extractSubsystems()[%d] = %q, want %q", i, s, tt.expected[i])
				}
			}
		})
	}
}

func TestEventlogDarwinToggleOutput(t *testing.T) {
	// Test enable action contains expected guidance
	result := eventlogDarwinToggle("enable", "com.apple.xpc")
	if result.Status != "success" {
		t.Errorf("eventlogDarwinToggle(enable) status = %q, want success", result.Status)
	}
	output := result.Output
	if !strings.Contains(output, "level:debug") {
		t.Error("enable output should mention level:debug")
	}
	if !strings.Contains(output, "com.apple.xpc") {
		t.Error("enable output should include the specified subsystem")
	}

	// Test disable action
	result = eventlogDarwinToggle("disable", "")
	if result.Status != "success" {
		t.Errorf("eventlogDarwinToggle(disable) status = %q, want success", result.Status)
	}
	output = result.Output
	if !strings.Contains(output, "level:default") {
		t.Error("disable output should mention level:default")
	}
}

func TestEventlogDarwinClearGuidance(t *testing.T) {
	// When no file path given, should return guidance
	result := eventlogDarwinClear("")
	if result.Status != "success" {
		t.Errorf("eventlogDarwinClear() status = %q, want success", result.Status)
	}
	output := result.Output
	if !strings.Contains(output, "log erase") {
		t.Error("clear output should mention 'log erase'")
	}
	if !strings.Contains(output, "SIP") {
		t.Error("clear output should mention SIP")
	}
}
