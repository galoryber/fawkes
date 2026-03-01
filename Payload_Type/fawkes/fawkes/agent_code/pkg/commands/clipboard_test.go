package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestClipboardName(t *testing.T) {
	cmd := &ClipboardCommand{}
	if cmd.Name() != "clipboard" {
		t.Errorf("expected 'clipboard', got '%s'", cmd.Name())
	}
}

func TestClipboardDescription(t *testing.T) {
	cmd := &ClipboardCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestClipboardInvalidJSON(t *testing.T) {
	cmd := &ClipboardCommand{}
	result := cmd.Execute(structs.Task{Params: "not-json"})
	if result.Status != "error" {
		t.Errorf("expected error status for invalid JSON, got '%s'", result.Status)
	}
	if !result.Completed {
		t.Error("should be completed on error")
	}
}

func TestClipboardUnknownAction(t *testing.T) {
	cmd := &ClipboardCommand{}
	params, _ := json.Marshal(ClipboardParams{Action: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got '%s'", result.Status)
	}
	if result.Output == "" {
		t.Error("error output should not be empty")
	}
}

func TestClipboardWriteRequiresData(t *testing.T) {
	cmd := &ClipboardCommand{}
	params, _ := json.Marshal(ClipboardParams{Action: "write", Data: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for write without data, got '%s'", result.Status)
	}
}

func TestDetectCredPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "NTLM hash",
			input:    "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
			expected: []string{"NTLM Hash"},
		},
		{
			name:     "NT hash only",
			input:    "31d6cfe0d16ae931b73c59d7e0c089c0",
			expected: []string{"NT Hash"},
		},
		{
			name:     "password pattern",
			input:    "password=SuperSecret123",
			expected: []string{"Password-like"},
		},
		{
			name:     "AWS key",
			input:    "AKIAIOSFODNN7EXAMPLE",
			expected: []string{"AWS Key"},
		},
		{
			name:     "private key header",
			input:    "-----BEGIN RSA PRIVATE KEY-----",
			expected: []string{"Private Key"},
		},
		{
			name:     "bearer token",
			input:    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			expected: []string{"Bearer Token"},
		},
		{
			name:     "connection string",
			input:    "Server=myserver;Database=mydb;Password=secret123",
			expected: []string{"Password-like", "Connection String"},
		},
		{
			name:     "UNC path",
			input:    `\\fileserver\share$\documents`,
			expected: []string{"UNC Path"},
		},
		{
			name:     "URL with creds",
			input:    "https://admin:password@example.com/api",
			expected: []string{"URL with Creds"},
		},
		{
			name:     "IP address",
			input:    "Connected to 192.168.1.1",
			expected: []string{"IP Address"},
		},
		{
			name:     "plain text",
			input:    "Hello, world!",
			expected: nil,
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := detectCredPatterns(tt.input)
			if len(tags) != len(tt.expected) {
				t.Errorf("expected %d tags %v, got %d tags %v", len(tt.expected), tt.expected, len(tags), tags)
				return
			}
			for i, tag := range tags {
				if tag != tt.expected[i] {
					t.Errorf("tag[%d]: expected '%s', got '%s'", i, tt.expected[i], tag)
				}
			}
		})
	}
}

func TestDetectCredPatternsNoDuplicates(t *testing.T) {
	// A string matching the same pattern multiple times should only tag once
	tags := detectCredPatterns("password=abc password=xyz")
	count := 0
	for _, tag := range tags {
		if tag == "Password-like" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected Password-like to appear at most once, got %d", count)
	}
}

func TestFormatClipEntriesStopped(t *testing.T) {
	entries := []clipEntry{}
	output := formatClipEntries(entries, 0, true)
	if output == "" {
		t.Error("output should not be empty")
	}
	if !strings.Contains(output, "stopped") {
		t.Error("output should mention 'stopped'")
	}
	if !strings.Contains(output, "Captures: 0") {
		t.Error("output should show 0 captures")
	}
}

func TestFormatClipEntriesRunning(t *testing.T) {
	entries := []clipEntry{}
	output := formatClipEntries(entries, 0, false)
	if !strings.Contains(output, "running") {
		t.Error("output should mention 'running'")
	}
}

func TestFormatClipEntriesWithTags(t *testing.T) {
	entries := []clipEntry{
		{Content: "test content", Tags: []string{"IP Address"}},
	}
	output := formatClipEntries(entries, 0, true)
	if !strings.Contains(output, "IP Address") {
		t.Error("output should include tags")
	}
	if !strings.Contains(output, "test content") {
		t.Error("output should include content")
	}
}

func TestFormatClipEntriesTruncation(t *testing.T) {
	longContent := make([]byte, 3000)
	for i := range longContent {
		longContent[i] = 'A'
	}
	entries := []clipEntry{
		{Content: string(longContent)},
	}
	output := formatClipEntries(entries, 0, true)
	if !strings.Contains(output, "truncated") {
		t.Error("output should mention truncation for content > 2000 chars")
	}
}

func TestClipMonitorStopWhenNotRunning(t *testing.T) {
	// Ensure monitor is stopped
	cm.mu.Lock()
	cm.running = false
	cm.mu.Unlock()

	result := clipMonitorStop()
	if result.Status != "error" {
		t.Errorf("expected error when stopping non-running monitor, got '%s'", result.Status)
	}
}

func TestClipMonitorDumpWhenNotRunning(t *testing.T) {
	cm.mu.Lock()
	cm.running = false
	cm.mu.Unlock()

	result := clipMonitorDump()
	if result.Status != "error" {
		t.Errorf("expected error when dumping non-running monitor, got '%s'", result.Status)
	}
}
