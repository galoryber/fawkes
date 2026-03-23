package commands

import (
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

// --- detectCredPatterns ---

func TestDetectCredPatterns_NTLMHash(t *testing.T) {
	tags := detectCredPatterns("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
	if !containsTag(tags, "NTLM Hash") {
		t.Errorf("expected NTLM Hash tag, got %v", tags)
	}
}

func TestDetectCredPatterns_NTHash(t *testing.T) {
	tags := detectCredPatterns("31d6cfe0d16ae931b73c59d7e0c089c0")
	if !containsTag(tags, "NT Hash") {
		t.Errorf("expected NT Hash tag, got %v", tags)
	}
}

func TestDetectCredPatterns_PasswordLike(t *testing.T) {
	tests := []string{
		"password=SuperSecret123",
		"Password: MyP@ss!",
		"passwd=test",
		"PWD=hunter2",
	}
	for _, input := range tests {
		tags := detectCredPatterns(input)
		if !containsTag(tags, "Password-like") {
			t.Errorf("expected Password-like tag for %q, got %v", input, tags)
		}
	}
}

func TestDetectCredPatterns_APIKey(t *testing.T) {
	tests := []string{
		"api_key=sk-1234567890abcdef",
		"apikey: my-secret-key",
		"api-token=ghp_abcdef1234567890",
		"access_token=eyJhbGciOi",
	}
	for _, input := range tests {
		tags := detectCredPatterns(input)
		if !containsTag(tags, "API Key") {
			t.Errorf("expected API Key tag for %q, got %v", input, tags)
		}
	}
}

func TestDetectCredPatterns_AWSKey(t *testing.T) {
	tags := detectCredPatterns("AKIAIOSFODNN7EXAMPLE")
	if !containsTag(tags, "AWS Key") {
		t.Errorf("expected AWS Key tag, got %v", tags)
	}
}

func TestDetectCredPatterns_PrivateKey(t *testing.T) {
	tests := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
	}
	for _, input := range tests {
		tags := detectCredPatterns(input)
		if !containsTag(tags, "Private Key") {
			t.Errorf("expected Private Key tag for %q, got %v", input, tags)
		}
	}
}

func TestDetectCredPatterns_BearerToken(t *testing.T) {
	tags := detectCredPatterns("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI")
	if !containsTag(tags, "Bearer Token") {
		t.Errorf("expected Bearer Token tag, got %v", tags)
	}
}

func TestDetectCredPatterns_ConnectionString(t *testing.T) {
	tags := detectCredPatterns("Server=myserver;Database=mydb;Password=secret123;")
	if !containsTag(tags, "Connection String") {
		t.Errorf("expected Connection String tag, got %v", tags)
	}
}

func TestDetectCredPatterns_Base64Blob(t *testing.T) {
	tags := detectCredPatterns("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmc=")
	if !containsTag(tags, "Base64 Blob") {
		t.Errorf("expected Base64 Blob tag, got %v", tags)
	}
}

func TestDetectCredPatterns_UNCPath(t *testing.T) {
	tags := detectCredPatterns(`\\fileserver\share$\folder`)
	if !containsTag(tags, "UNC Path") {
		t.Errorf("expected UNC Path tag, got %v", tags)
	}
}

func TestDetectCredPatterns_URLWithCreds(t *testing.T) {
	tags := detectCredPatterns("https://admin:password123@internal.corp.local/api")
	if !containsTag(tags, "URL with Creds") {
		t.Errorf("expected URL with Creds tag, got %v", tags)
	}
}

func TestDetectCredPatterns_IPAddress(t *testing.T) {
	tags := detectCredPatterns("Connected to 192.168.1.100 on port 445")
	if !containsTag(tags, "IP Address") {
		t.Errorf("expected IP Address tag, got %v", tags)
	}
}

func TestDetectCredPatterns_MultipleTags(t *testing.T) {
	// A URL with embedded creds and IP should match multiple patterns
	tags := detectCredPatterns("https://admin:password123@192.168.1.100/api")
	if len(tags) < 2 {
		t.Errorf("expected multiple tags (URL with Creds + IP Address), got %v", tags)
	}
}

func TestDetectCredPatterns_NoDuplicates(t *testing.T) {
	tags := detectCredPatterns("password=test password=other")
	count := 0
	for _, tag := range tags {
		if tag == "Password-like" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected no duplicate tags, got %d Password-like tags", count)
	}
}

func TestDetectCredPatterns_NoMatch(t *testing.T) {
	tags := detectCredPatterns("Hello World! This is just normal text.")
	if len(tags) != 0 {
		t.Errorf("expected no tags for normal text, got %v", tags)
	}
}

func TestDetectCredPatterns_Empty(t *testing.T) {
	tags := detectCredPatterns("")
	if len(tags) != 0 {
		t.Errorf("expected no tags for empty string, got %v", tags)
	}
}

// --- formatClipEntries ---

func TestFormatClipEntries_Stopped(t *testing.T) {
	entries := []clipEntry{
		{
			Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			Content:   "test content",
			Tags:      nil,
		},
	}
	output := formatClipEntries(entries, 30*time.Second, true)
	if !strings.Contains(output, "Clipboard monitor stopped") {
		t.Error("expected 'stopped' message")
	}
	if !strings.Contains(output, "Captures: 1") {
		t.Error("expected capture count")
	}
	if !strings.Contains(output, "test content") {
		t.Error("expected content in output")
	}
}

func TestFormatClipEntries_Running(t *testing.T) {
	entries := []clipEntry{}
	output := formatClipEntries(entries, 10*time.Second, false)
	if !strings.Contains(output, "Clipboard monitor running") {
		t.Error("expected 'running' message")
	}
	if !strings.Contains(output, "Captures: 0") {
		t.Error("expected 0 captures")
	}
	if !strings.Contains(output, "No clipboard changes captured") {
		t.Error("expected 'no changes' message")
	}
}

func TestFormatClipEntries_WithTags(t *testing.T) {
	entries := []clipEntry{
		{
			Timestamp: time.Date(2026, 1, 1, 14, 30, 0, 0, time.UTC),
			Content:   "password=secret",
			Tags:      []string{"Password-like"},
		},
	}
	output := formatClipEntries(entries, 60*time.Second, false)
	if !strings.Contains(output, "Tags: Password-like") {
		t.Error("expected tags in output")
	}
	if !strings.Contains(output, "Capture #1") {
		t.Error("expected capture number")
	}
}

func TestFormatClipEntries_Truncation(t *testing.T) {
	longContent := strings.Repeat("A", 3000)
	entries := []clipEntry{
		{
			Timestamp: time.Now(),
			Content:   longContent,
			Tags:      nil,
		},
	}
	output := formatClipEntries(entries, time.Minute, false)
	if !strings.Contains(output, "truncated") {
		t.Error("expected truncation notice")
	}
	if strings.Contains(output, strings.Repeat("A", 2500)) {
		t.Error("content should be truncated to ~2000 chars")
	}
}

func TestFormatClipEntries_MultipleEntries(t *testing.T) {
	entries := []clipEntry{
		{Timestamp: time.Now(), Content: "first", Tags: nil},
		{Timestamp: time.Now(), Content: "second", Tags: []string{"IP Address"}},
		{Timestamp: time.Now(), Content: "third", Tags: nil},
	}
	output := formatClipEntries(entries, 5*time.Minute, true)
	if !strings.Contains(output, "Captures: 3") {
		t.Error("expected 3 captures")
	}
	if !strings.Contains(output, "Capture #1") || !strings.Contains(output, "Capture #3") {
		t.Error("expected all capture numbers")
	}
}

func TestFormatClipEntries_Empty(t *testing.T) {
	output := formatClipEntries(nil, 0, true)
	if !strings.Contains(output, "Captures: 0") {
		t.Error("expected 0 captures")
	}
	if !strings.Contains(output, "No clipboard changes captured") {
		t.Error("expected empty message")
	}
}

// --- Execute routing ---

func TestClipboardExecuteInvalidJSON(t *testing.T) {
	cmd := &ClipboardCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" || !strings.Contains(result.Output, "parsing parameters") {
		t.Errorf("expected parse error, got: %s", result.Output)
	}
}

func TestClipboardExecuteUnknownAction(t *testing.T) {
	cmd := &ClipboardCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got: %s", result.Output)
	}
}

func TestClipboardExecuteWriteMissingData(t *testing.T) {
	cmd := &ClipboardCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"write"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "data") {
		t.Errorf("expected missing data error, got: %s", result.Output)
	}
}

func TestClipboardExecuteStopNotRunning(t *testing.T) {
	// Ensure monitor is not running
	cm.mu.Lock()
	cm.running = false
	cm.mu.Unlock()

	cmd := &ClipboardCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"stop"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "not running") {
		t.Errorf("expected 'not running' error for stop, got: %s", result.Output)
	}
}

func TestClipboardExecuteDumpNotRunning(t *testing.T) {
	// Ensure monitor is not running
	cm.mu.Lock()
	cm.running = false
	cm.mu.Unlock()

	cmd := &ClipboardCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"dump"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "not running") {
		t.Errorf("expected 'not running' error for dump, got: %s", result.Output)
	}
}

// --- helper ---

func containsTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}
