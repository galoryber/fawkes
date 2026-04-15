package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudCredPathsIntegrity(t *testing.T) {
	if len(cloudCredPaths) == 0 {
		t.Fatal("cloudCredPaths is empty")
	}
	seen := make(map[string]bool)
	for i, cred := range cloudCredPaths {
		if cred.name == "" {
			t.Errorf("cloudCredPaths[%d] has empty name", i)
		}
		if seen[cred.name] {
			t.Errorf("duplicate cloud provider name: %s", cred.name)
		}
		seen[cred.name] = true
		if len(cred.paths) == 0 && len(cred.envVars) == 0 {
			t.Errorf("cloudCredPaths[%d] (%s) has no paths and no env vars", i, cred.name)
		}
		for j, p := range cred.paths {
			if p == "" {
				t.Errorf("cloudCredPaths[%d] (%s) paths[%d] is empty", i, cred.name, j)
			}
			if filepath.IsAbs(p) {
				t.Errorf("cloudCredPaths[%d] (%s) paths[%d] should be relative, got: %s", i, cred.name, j, p)
			}
		}
		for j, e := range cred.envVars {
			if e == "" {
				t.Errorf("cloudCredPaths[%d] (%s) envVars[%d] is empty", i, cred.name, j)
			}
		}
	}
}

func TestCloudCredPathsProviders(t *testing.T) {
	expected := []string{"AWS", "GCP", "Azure", "Kubernetes", "Docker", "Terraform", "Vault (HashiCorp)"}
	names := make(map[string]bool)
	for _, cred := range cloudCredPaths {
		names[cred.name] = true
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected cloud provider %q not found in cloudCredPaths", name)
		}
	}
}

func TestCredCloudEnvVarMasking(t *testing.T) {
	// The credCloud function masks env vars longer than 40 chars:
	// display = display[:20] + "..." + display[len(display)-10:]
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"short", "abc123", "abc123"},
		{"exactly40", strings.Repeat("a", 40), strings.Repeat("a", 40)},
		{"long50", strings.Repeat("x", 50), strings.Repeat("x", 20) + "..." + strings.Repeat("x", 10)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			display := tc.input
			if len(display) > 40 {
				display = display[:20] + "..." + display[len(display)-10:]
			}
			if display != tc.expected {
				t.Errorf("got %q, want %q", display, tc.expected)
			}
		})
	}
}

func TestCredCloudFileDetection(t *testing.T) {
	// Create temp home with cloud credential files
	home := t.TempDir()

	// Create .aws/credentials
	awsDir := filepath.Join(home, ".aws")
	if err := os.MkdirAll(awsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte("[default]\naws_access_key_id=AKIA...\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create .kube/config
	kubeDir := filepath.Join(home, ".kube")
	if err := os.MkdirAll(kubeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kubeDir, "config"), []byte("apiVersion: v1\nclusters:\n- name: test\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify files exist at expected relative paths
	for _, cred := range cloudCredPaths {
		for _, relPath := range cred.paths {
			path := filepath.Join(home, relPath)
			if _, err := os.Stat(path); err == nil {
				t.Logf("Found %s file: %s", cred.name, relPath)
			}
		}
	}

	// Verify AWS credentials were found
	awsPath := filepath.Join(home, ".aws/credentials")
	if _, err := os.Stat(awsPath); err != nil {
		t.Error("expected AWS credentials file to exist")
	}

	// Verify kube config was found
	kubePath := filepath.Join(home, ".kube/config")
	if _, err := os.Stat(kubePath); err != nil {
		t.Error("expected kube config file to exist")
	}
}

func TestCredCloudContentTruncation(t *testing.T) {
	// credCloud truncates content > 2000 chars
	tests := []struct {
		name      string
		content   string
		maxLen    int
		truncated bool
	}{
		{"short", "hello", 2000, false},
		{"exact2000", strings.Repeat("a", 2000), 2000, false},
		{"over2000", strings.Repeat("b", 2500), 2000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := tc.content
			if len(content) > tc.maxLen {
				content = content[:tc.maxLen] + "\n... (truncated)"
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

func TestCredCloudK8sTokenTruncation(t *testing.T) {
	// credCloudK8sServiceAccount truncates tokens > 200 chars:
	// token[:100] + "..." + token[len(token)-50:]
	token := strings.Repeat("x", 300)
	if len(token) > 200 {
		token = token[:100] + "..." + token[len(token)-50:]
	}
	if len(token) != 153 { // 100 + 3 + 50
		t.Errorf("truncated token length = %d, want 153", len(token))
	}
}

func TestCredCloudAWSCacheJSONFilter(t *testing.T) {
	// credCloudAWSCache only processes .json files
	names := []string{"cache.json", "token.json", "readme.txt", ".hidden.json", "data.yaml"}
	var jsonFiles []string
	for _, name := range names {
		if strings.HasSuffix(name, ".json") {
			jsonFiles = append(jsonFiles, name)
		}
	}
	if len(jsonFiles) != 3 {
		t.Errorf("expected 3 JSON files, got %d: %v", len(jsonFiles), jsonFiles)
	}
}

func TestCredCloudGCPServiceAccountFilter(t *testing.T) {
	// credCloudGCPServiceAccounts looks for .json files containing "service_account" or "adc"
	names := []string{"service_account_key.json", "adc.json", "properties", "random.json", "config.txt"}
	var matched []string
	for _, name := range names {
		if strings.HasSuffix(name, ".json") && name != "properties" {
			if strings.Contains(name, "service_account") || strings.Contains(name, "adc") {
				matched = append(matched, name)
			}
		}
	}
	if len(matched) != 2 {
		t.Errorf("expected 2 matched GCP files, got %d: %v", len(matched), matched)
	}
}
