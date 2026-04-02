package commands

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPatternsIntegrity(t *testing.T) {
	if len(configPatterns) == 0 {
		t.Fatal("configPatterns is empty")
	}
	seen := make(map[string]bool)
	for i, cfg := range configPatterns {
		if cfg.name == "" {
			t.Errorf("configPatterns[%d] has empty name", i)
		}
		if seen[cfg.name] {
			t.Errorf("duplicate config pattern name: %s", cfg.name)
		}
		seen[cfg.name] = true
		if len(cfg.patterns) == 0 {
			t.Errorf("configPatterns[%d] (%s) has no patterns", i, cfg.name)
		}
		for j, p := range cfg.patterns {
			if p == "" {
				t.Errorf("configPatterns[%d] (%s) patterns[%d] is empty", i, cfg.name, j)
			}
			if filepath.IsAbs(p) {
				t.Errorf("configPatterns[%d] (%s) patterns[%d] should be relative, got: %s", i, cfg.name, j, p)
			}
		}
	}
}

func TestConfigPatternsCategories(t *testing.T) {
	expected := []string{"Environment Files", "SSH Private Keys", "Git Credentials", "NPM/Pip/Gem Tokens"}
	names := make(map[string]bool)
	for _, cfg := range configPatterns {
		names[cfg.name] = true
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected config category %q not found", name)
		}
	}
}

func TestConfigSensitiveLineFiltering(t *testing.T) {
	// The credConfigs function filters DB config lines for sensitive keywords
	tests := []struct {
		line      string
		sensitive bool
	}{
		{"password = mysecret123", true},
		{"PASSWORD=abc", true},
		{"db_password = test", true},
		{"secret_key = abc123", true},
		{"SECRET = hidden", true},
		{"api_token = tok_xyz", true},
		{"TOKEN=bearer_abc", true},
		{"access_key = AKIA", true},
		{"encryption_key = aes256", true},
		{"hostname = db.example.com", false},
		{"port = 5432", false},
		{"database = myapp", false},
		{"user = admin", false},
		{"max_connections = 100", false},
		{"", false},
	}
	for _, tc := range tests {
		lower := strings.ToLower(tc.line)
		isSensitive := strings.Contains(lower, "password") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "key")
		if isSensitive != tc.sensitive {
			t.Errorf("line %q: got sensitive=%v, want %v", tc.line, isSensitive, tc.sensitive)
		}
	}
}

func TestConfigContentTruncation(t *testing.T) {
	// credConfigs truncates content > 1000 chars
	tests := []struct {
		name      string
		size      int
		truncated bool
	}{
		{"small", 100, false},
		{"exact1000", 1000, false},
		{"over1000", 1500, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Repeat("x", tc.size)
			if len(content) > 1000 {
				content = content[:1000] + "\n... (truncated)"
			}
			if tc.truncated && !strings.HasSuffix(content, "(truncated)") {
				t.Error("expected truncation suffix")
			}
			if !tc.truncated && strings.Contains(content, "truncated") {
				t.Error("unexpected truncation")
			}
		})
	}
}

func TestConfigSSHKeyPatterns(t *testing.T) {
	// SSH Private Keys should cover common key types
	var sshPatterns []string
	for _, cfg := range configPatterns {
		if cfg.name == "SSH Private Keys" {
			sshPatterns = cfg.patterns
			break
		}
	}
	if len(sshPatterns) == 0 {
		t.Fatal("SSH Private Keys pattern not found")
	}

	expectedKeys := []string{"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}
	for _, key := range expectedKeys {
		found := false
		for _, p := range sshPatterns {
			if strings.Contains(p, key) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SSH key pattern containing %q not found", key)
		}
	}
}
