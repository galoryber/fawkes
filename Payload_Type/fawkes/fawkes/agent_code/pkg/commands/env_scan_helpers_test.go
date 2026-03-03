//go:build !windows

package commands

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseEnvironBlock(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []string
	}{
		{
			name:     "basic vars",
			input:    []byte("HOME=/root\x00PATH=/usr/bin\x00USER=root\x00"),
			expected: []string{"HOME=/root", "PATH=/usr/bin", "USER=root"},
		},
		{
			name:     "empty",
			input:    []byte{},
			expected: nil,
		},
		{
			name:     "single var",
			input:    []byte("AWS_SECRET_KEY=abc123\x00"),
			expected: []string{"AWS_SECRET_KEY=abc123"},
		},
		{
			name:     "trailing nulls",
			input:    []byte("A=1\x00B=2\x00\x00\x00"),
			expected: []string{"A=1", "B=2"},
		},
		{
			name:     "no trailing null",
			input:    []byte("X=1\x00Y=2"),
			expected: []string{"X=1", "Y=2"},
		},
		{
			name:     "entries without equals sign skipped",
			input:    []byte("VALID=yes\x00invalid-no-equals\x00ALSO_VALID=yes\x00"),
			expected: []string{"VALID=yes", "ALSO_VALID=yes"},
		},
		{
			name:     "values with equals signs",
			input:    []byte("URL=http://host?a=1&b=2\x00"),
			expected: []string{"URL=http://host?a=1&b=2"},
		},
		{
			name:     "empty value",
			input:    []byte("EMPTY=\x00FULL=yes\x00"),
			expected: []string{"EMPTY=", "FULL=yes"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEnvironBlock(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d vars, got %d: %v", len(tt.expected), len(result), result)
			}
			for i, exp := range tt.expected {
				if result[i] != exp {
					t.Errorf("var[%d] = %q, want %q", i, result[i], exp)
				}
			}
		})
	}
}

func TestClassifyEnvVar(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		// API keys and tokens
		{"AWS_SECRET_ACCESS_KEY", "AWS Credential"},
		{"AWS_ACCESS_KEY_ID", "AWS Credential"},
		{"GITHUB_TOKEN", "GitHub Token"},
		{"API_KEY", "API Key"},
		{"MY_API_KEY", "API Key"},
		{"ACCESS_TOKEN", "Access Token"},

		// Passwords
		{"DB_PASSWORD", "Database Password"},
		{"MYSQL_PASSWORD", "MySQL Password"},
		{"POSTGRES_PASSWORD", "PostgreSQL Password"},
		{"REDIS_PASSWORD", "Redis Password"},
		{"SMTP_PASSWORD", "SMTP Password"},

		// Cloud
		{"AZURE_CLIENT_SECRET", "Azure Credential"},
		{"GOOGLE_APPLICATION_CREDENTIALS", "GCP Credential"},

		// Database URLs
		{"DATABASE_URL", "Database URL"},
		{"MONGO_URI", "MongoDB URI"},
		{"CONNECTION_STRING", "Connection String"},

		// Container
		{"KUBECONFIG", "Kubernetes Config"},
		{"DOCKER_PASSWORD", "Docker Credential"},

		// JWT/crypto
		{"JWT_SECRET", "JWT Secret"},
		{"SIGNING_KEY", "Signing Key"},
		{"PRIVATE_KEY", "Private Key"},

		// Non-sensitive (should return empty)
		{"HOME", ""},
		{"PATH", ""},
		{"USER", ""},
		{"SHELL", ""},
		{"LANG", ""},
		{"TERM", ""},
		{"DISPLAY", ""},
		{"HOSTNAME", ""},
		{"XDG_RUNTIME_DIR", ""},
	}

	for _, tt := range tests {
		result := classifyEnvVar(tt.name)
		if result != tt.expected {
			t.Errorf("classifyEnvVar(%q) = %q, want %q", tt.name, result, tt.expected)
		}
	}
}

func TestClassifyEnvVarCaseInsensitive(t *testing.T) {
	// Should match regardless of case
	tests := []string{
		"aws_secret_access_key",
		"Aws_Secret_Access_Key",
		"AWS_SECRET_ACCESS_KEY",
	}

	for _, name := range tests {
		result := classifyEnvVar(name)
		if result == "" {
			t.Errorf("classifyEnvVar(%q) should match (case-insensitive)", name)
		}
	}
}

func TestRedactValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "short"},           // <= 12 chars: no redaction
		{"exactly12ch", "exactly12ch"}, // exactly 12: no redaction
		{"this-is-a-long-secret-key", "this...-key"}, // > 12: redacted
		{"AKIAIOSFODNN7EXAMPLE", "AKIA...MPLE"},     // AWS-style key
		{"a", "a"},                                    // single char
		{"", ""},                                      // empty
		{"123456789012", "123456789012"},               // exactly 12
		{"1234567890123", "1234...0123"},               // 13 chars
	}

	for _, tt := range tests {
		result := redactValue(tt.input)
		if result != tt.expected {
			t.Errorf("redactValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestFilterSensitiveVars(t *testing.T) {
	envVars := []string{
		"HOME=/root",
		"PATH=/usr/bin",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"USER=root",
		"DATABASE_URL=postgres://user:pass@localhost/db",
		"SHELL=/bin/bash",
		"API_KEY=sk-test-1234",
	}

	results := filterSensitiveVars(envVars, 123, "myapp")

	if len(results) != 3 {
		t.Fatalf("expected 3 sensitive vars, got %d", len(results))
	}

	// Verify PIDs and process names are set
	for _, r := range results {
		if r.PID != 123 {
			t.Errorf("expected PID 123, got %d", r.PID)
		}
		if r.Process != "myapp" {
			t.Errorf("expected process 'myapp', got %q", r.Process)
		}
	}

	// Verify the sensitive vars are found
	found := make(map[string]bool)
	for _, r := range results {
		found[r.Variable] = true
	}
	for _, expected := range []string{"AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "API_KEY"} {
		if !found[expected] {
			t.Errorf("expected to find %q in results", expected)
		}
	}
}

func TestFilterSensitiveVarsNoSensitive(t *testing.T) {
	envVars := []string{
		"HOME=/root",
		"PATH=/usr/bin",
		"USER=root",
	}

	results := filterSensitiveVars(envVars, 1, "init")
	if len(results) != 0 {
		t.Errorf("expected 0 sensitive vars, got %d", len(results))
	}
}

func TestFilterSensitiveVarsRedaction(t *testing.T) {
	envVars := []string{
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	results := filterSensitiveVars(envVars, 1, "app")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Value should be redacted (> 12 chars)
	if !strings.Contains(results[0].Value, "...") {
		t.Errorf("expected redacted value, got %q", results[0].Value)
	}
}

func TestFormatEnvScanResultsEmpty(t *testing.T) {
	result := formatEnvScanResults(nil, 100, 50)
	if !strings.Contains(result, "Process Environment Variable Scan") {
		t.Error("missing header")
	}
	if !strings.Contains(result, "Processes scanned: 50 / 100") {
		t.Error("missing process count")
	}
	if !strings.Contains(result, "Sensitive variables found: 0") {
		t.Error("missing variable count")
	}
	if !strings.Contains(result, "No sensitive environment variables detected") {
		t.Error("missing no-results message")
	}
}

func TestFormatEnvScanResultsWithFindings(t *testing.T) {
	results := []envScanResult{
		{PID: 100, Process: "webapp", Variable: "API_KEY", Value: "sk-t...1234", Category: "API Key"},
		{PID: 200, Process: "worker", Variable: "DATABASE_URL", Value: "post...b/db", Category: "Database URL"},
		{PID: 100, Process: "webapp", Variable: "JWT_SECRET", Value: "my-s...cret", Category: "JWT Secret"},
	}

	output := formatEnvScanResults(results, 500, 200)

	if !strings.Contains(output, "Sensitive variables found: 3") {
		t.Error("missing finding count")
	}
	if !strings.Contains(output, "--- API Key (1) ---") {
		t.Error("missing API Key category")
	}
	if !strings.Contains(output, "--- Database URL (1) ---") {
		t.Error("missing Database URL category")
	}
	if !strings.Contains(output, "--- JWT Secret (1) ---") {
		t.Error("missing JWT Secret category")
	}
	if !strings.Contains(output, "[PID 100] webapp: API_KEY") {
		t.Error("missing API_KEY entry")
	}
	if !strings.Contains(output, "[PID 200] worker: DATABASE_URL") {
		t.Error("missing DATABASE_URL entry")
	}
}

func TestFormatEnvScanResultsCategoryGrouping(t *testing.T) {
	results := []envScanResult{
		{PID: 1, Process: "a", Variable: "AWS_SECRET_ACCESS_KEY", Value: "val1", Category: "AWS Credential"},
		{PID: 2, Process: "b", Variable: "AWS_ACCESS_KEY_ID", Value: "val2", Category: "AWS Credential"},
		{PID: 3, Process: "c", Variable: "DB_PASSWORD", Value: "val3", Category: "Database Password"},
	}

	output := formatEnvScanResults(results, 10, 10)
	if !strings.Contains(output, "--- AWS Credential (2) ---") {
		t.Error("expected 2 AWS Credential findings grouped together")
	}
	if !strings.Contains(output, "--- Database Password (1) ---") {
		t.Error("expected 1 Database Password finding")
	}
}

func TestFormatEnvScanResultsCategoriesSorted(t *testing.T) {
	results := []envScanResult{
		{PID: 1, Process: "a", Variable: "Z_TOKEN", Value: "v", Category: "Zzz"},
		{PID: 2, Process: "b", Variable: "A_KEY", Value: "v", Category: "Aaa"},
	}

	output := formatEnvScanResults(results, 10, 10)
	aIdx := strings.Index(output, "--- Aaa")
	zIdx := strings.Index(output, "--- Zzz")
	if aIdx < 0 || zIdx < 0 {
		t.Fatal("missing category headers")
	}
	if aIdx > zIdx {
		t.Error("categories should be sorted alphabetically")
	}
}

func TestApplyEnvFilter(t *testing.T) {
	results := []envScanResult{
		{Variable: "AWS_SECRET_ACCESS_KEY", Category: "AWS Credential"},
		{Variable: "DATABASE_URL", Category: "Database URL"},
		{Variable: "API_KEY", Category: "API Key"},
	}

	// Filter by variable name
	filtered := applyEnvFilter(results, "aws")
	if len(filtered) != 1 || filtered[0].Variable != "AWS_SECRET_ACCESS_KEY" {
		t.Errorf("expected 1 AWS result, got %d", len(filtered))
	}

	// Filter by category
	filtered = applyEnvFilter(results, "database")
	if len(filtered) != 1 || filtered[0].Variable != "DATABASE_URL" {
		t.Errorf("expected 1 Database result, got %d", len(filtered))
	}

	// Filter matching multiple
	filtered = applyEnvFilter(results, "key")
	if len(filtered) != 2 {
		t.Errorf("expected 2 results matching 'key', got %d", len(filtered))
	}

	// Filter matching nothing
	filtered = applyEnvFilter(results, "nonexistent")
	if len(filtered) != 0 {
		t.Errorf("expected 0 results, got %d", len(filtered))
	}
}

func TestSensitiveEnvPatternsCompleteness(t *testing.T) {
	// Ensure we have patterns for all major credential categories
	categories := make(map[string]bool)
	for _, p := range sensitiveEnvPatterns {
		categories[p.Category] = true
	}

	required := []string{
		"API Key",
		"Password",
		"Secret",
		"Access Key",
		"AWS Credential",
		"Azure Credential",
		"GCP Credential",
		"Database URL",
		"GitHub Token",
		"JWT Secret",
		"Kubernetes Config",
	}

	for _, cat := range required {
		if !categories[cat] {
			t.Errorf("missing required credential category: %s", cat)
		}
	}
}

func TestSensitiveEnvPatternsNotEmpty(t *testing.T) {
	if len(sensitiveEnvPatterns) < 20 {
		t.Errorf("expected at least 20 sensitive patterns, got %d", len(sensitiveEnvPatterns))
	}

	for _, p := range sensitiveEnvPatterns {
		if p.Pattern == "" {
			t.Error("pattern should not be empty")
		}
		if p.Category == "" {
			t.Error("category should not be empty")
		}
	}
}

func TestEnvScanCommandName(t *testing.T) {
	cmd := &EnvScanCommand{}
	if cmd.Name() != "env-scan" {
		t.Errorf("expected 'env-scan', got %q", cmd.Name())
	}
}

func TestEnvScanCommandDescription(t *testing.T) {
	cmd := &EnvScanCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "environment") {
		t.Error("description should mention environment")
	}
	if !strings.Contains(desc, "T1057") || !strings.Contains(desc, "T1552") {
		t.Error("description should include MITRE ATT&CK IDs")
	}
}

func TestParseEnvironBlockLargeInput(t *testing.T) {
	// Simulate a real /proc/<pid>/environ with many variables
	var parts []string
	for i := 0; i < 100; i++ {
		parts = append(parts, fmt.Sprintf("VAR_%d=value_%d", i, i))
	}
	input := []byte(strings.Join(parts, "\x00") + "\x00")

	result := parseEnvironBlock(input)
	if len(result) != 100 {
		t.Errorf("expected 100 vars from large input, got %d", len(result))
	}
}

func TestFilterSensitiveVarsMalformedEntry(t *testing.T) {
	envVars := []string{
		"GOOD=value",
		"=empty-key",      // empty key
		"noequals",        // no equals (shouldn't happen after parseEnvironBlock)
		"API_KEY=value",   // sensitive
	}

	results := filterSensitiveVars(envVars, 1, "test")
	// Only API_KEY should be found
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestEnvScanResultStruct(t *testing.T) {
	r := envScanResult{
		PID:      42,
		Process:  "myservice",
		Variable: "SECRET_KEY",
		Value:    "test...alue",
		Category: "Secret",
	}

	if r.PID != 42 || r.Process != "myservice" || r.Variable != "SECRET_KEY" {
		t.Error("struct fields not set correctly")
	}
}
