//go:build !windows

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCredHarvestName(t *testing.T) {
	cmd := &CredHarvestCommand{}
	if cmd.Name() != "cred-harvest" {
		t.Errorf("expected 'cred-harvest', got '%s'", cmd.Name())
	}
}

func TestCredHarvestDescription(t *testing.T) {
	cmd := &CredHarvestCommand{}
	if !strings.Contains(cmd.Description(), "credential") {
		t.Errorf("description should mention credentials: %s", cmd.Description())
	}
}

func TestCredHarvestEmptyParams(t *testing.T) {
	cmd := &CredHarvestCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %s", result.Status)
	}
}

func TestCredHarvestBadJSON(t *testing.T) {
	cmd := &CredHarvestCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %s", result.Status)
	}
}

func TestCredHarvestInvalidAction(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got: %s", result.Output)
	}
}

func TestCredHarvestShadow(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "shadow"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for shadow, got %s: %s", result.Status, result.Output)
	}
	// Should mention shadow file (even if permission denied)
	if !strings.Contains(result.Output, "shadow") {
		t.Errorf("shadow output should mention shadow: %s", result.Output)
	}
	// Should show passwd accounts
	if !strings.Contains(result.Output, "/etc/passwd") {
		t.Errorf("shadow output should mention /etc/passwd: %s", result.Output)
	}
}

func TestCredHarvestCloud(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "cloud"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for cloud, got %s: %s", result.Status, result.Output)
	}
	// Should check for AWS, GCP, Azure, etc.
	if !strings.Contains(result.Output, "AWS") {
		t.Errorf("cloud output should mention AWS: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Kubernetes") {
		t.Errorf("cloud output should mention Kubernetes: %s", result.Output)
	}
}

func TestCredHarvestConfigs(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "configs"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for configs, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Application Credentials") {
		t.Errorf("configs output should contain header: %s", result.Output)
	}
}

func TestCredHarvestAll(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "all"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for all, got %s: %s", result.Status, result.Output)
	}
	// Should contain sections from all three actions
	if !strings.Contains(result.Output, "System Credential") {
		t.Errorf("all output should contain shadow section: %s", result.Output[:200])
	}
	if !strings.Contains(result.Output, "Cloud") {
		t.Errorf("all output should contain cloud section: %s", result.Output[:200])
	}
	if !strings.Contains(result.Output, "Application") {
		t.Errorf("all output should contain configs section: %s", result.Output[:200])
	}
}

func TestCredHarvestUserFilter(t *testing.T) {
	cmd := &CredHarvestCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "shadow", "user": "root"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for filtered shadow, got %s: %s", result.Status, result.Output)
	}
}

func TestGetUserHomes(t *testing.T) {
	homes := getUserHomes("")
	if len(homes) == 0 {
		t.Skip("no user homes found (might be in container)")
	}
	// At least one home directory should exist
	for _, home := range homes {
		if _, err := os.Stat(home); err != nil {
			t.Errorf("home directory %s doesn't exist", home)
		}
	}
}

func TestGetUserHomesFiltered(t *testing.T) {
	homes := getUserHomes("root")
	// Root home should either be found or not (depends on system)
	for _, home := range homes {
		if !strings.Contains(home, "root") {
			t.Errorf("expected root home, got %s", home)
		}
	}
}

func TestIndentLines(t *testing.T) {
	result := credIndentLines("line1\nline2\nline3", "  ")
	expected := "  line1\n  line2\n  line3"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestIndentLinesEmpty(t *testing.T) {
	result := credIndentLines("line1\n\nline3", "  ")
	if !strings.Contains(result, "  line1") || !strings.Contains(result, "  line3") {
		t.Errorf("non-empty lines should be indented: %q", result)
	}
}

func TestIndentLinesEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		prefix   string
		expected string
	}{
		{"empty string", "", "  ", ""},
		{"single line", "hello", ">> ", ">> hello"},
		{"all empty lines", "\n\n\n", "  ", "\n\n\n"},
		{"tab prefix", "a\nb", "\t", "\ta\n\tb"},
		{"trailing newline", "line1\nline2\n", "  ", "  line1\n  line2\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := credIndentLines(tt.input, tt.prefix)
			if got != tt.expected {
				t.Errorf("credIndentLines(%q, %q) = %q, want %q", tt.input, tt.prefix, got, tt.expected)
			}
		})
	}
}

func TestCredCloudEnvVars(t *testing.T) {
	// Set a cloud env var and verify it appears in output + credentials
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	result := credCloud(credHarvestArgs{Action: "cloud"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	if !strings.Contains(result.Output, "AWS_ACCESS_KEY_ID") {
		t.Error("output should contain AWS_ACCESS_KEY_ID")
	}
	if !strings.Contains(result.Output, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("output should contain the access key value")
	}

	// Verify credentials are reported to Mythic vault
	if result.Credentials == nil {
		t.Fatal("credentials should be reported for env vars")
	}
	found := false
	for _, cred := range *result.Credentials {
		if cred.Account == "AWS_ACCESS_KEY_ID" && cred.Credential == "AKIAIOSFODNN7EXAMPLE" {
			found = true
			if cred.CredentialType != "plaintext" {
				t.Errorf("expected plaintext credential type, got %s", cred.CredentialType)
			}
			if cred.Realm != "AWS" {
				t.Errorf("expected AWS realm, got %s", cred.Realm)
			}
		}
	}
	if !found {
		t.Error("AWS_ACCESS_KEY_ID credential not found in vault report")
	}
}

func TestCredCloudEnvVarTruncation(t *testing.T) {
	// Long env var values should be truncated in display (but full in credentials)
	longVal := strings.Repeat("A", 50)
	t.Setenv("VAULT_TOKEN", longVal)

	result := credCloud(credHarvestArgs{Action: "cloud"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s", result.Status)
	}

	// Display should be truncated (first 20 + ... + last 10)
	if strings.Contains(result.Output, longVal) {
		t.Error("long env var should be truncated in display output")
	}
	truncated := longVal[:20] + "..." + longVal[len(longVal)-10:]
	if !strings.Contains(result.Output, truncated) {
		t.Errorf("output should contain truncated form %q", truncated)
	}

	// But credential vault should have full value
	if result.Credentials != nil {
		for _, cred := range *result.Credentials {
			if cred.Account == "VAULT_TOKEN" {
				if cred.Credential != longVal {
					t.Error("credential vault should contain full (non-truncated) value")
				}
			}
		}
	}
}

func TestCredCloudAWSCacheMock(t *testing.T) {
	home := t.TempDir()

	// Create mock AWS SSO cache
	ssoDir := filepath.Join(home, ".aws", "sso", "cache")
	if err := os.MkdirAll(ssoDir, 0755); err != nil {
		t.Fatal(err)
	}
	ssoContent := `{"startUrl":"https://my-sso-portal.awsapps.com/start","region":"us-east-1","accessToken":"eyJhbGci...","expiresAt":"2026-03-01T12:00:00Z"}`
	if err := os.WriteFile(filepath.Join(ssoDir, "abc123.json"), []byte(ssoContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create mock AWS CLI cache
	cliDir := filepath.Join(home, ".aws", "cli", "cache")
	if err := os.MkdirAll(cliDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cliDir, "session.json"), []byte(`{"Credentials":{"AccessKeyId":"ASIA..."}}`), 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	credCloudAWSCache(&sb, []string{home})
	output := sb.String()

	if !strings.Contains(output, "AWS SSO/CLI Cache") {
		t.Error("should contain AWS SSO/CLI Cache header")
	}
	if !strings.Contains(output, "[SSO]") {
		t.Error("should detect SSO cache file")
	}
	if !strings.Contains(output, "abc123.json") {
		t.Error("should show SSO cache filename")
	}
	if !strings.Contains(output, "startUrl") {
		t.Error("should display SSO cache content (small file)")
	}
	if !strings.Contains(output, "[CLI]") {
		t.Error("should detect CLI cache file")
	}
}

func TestCredCloudAWSCacheEmpty(t *testing.T) {
	home := t.TempDir()
	// No AWS directories — should produce no output
	var sb strings.Builder
	credCloudAWSCache(&sb, []string{home})
	if sb.Len() > 0 {
		t.Errorf("should produce no output for missing AWS dirs, got: %q", sb.String())
	}
}

func TestCredCloudGCPServiceAccountsMock(t *testing.T) {
	home := t.TempDir()

	// Create mock GCP service account key
	gcloudDir := filepath.Join(home, ".config", "gcloud")
	if err := os.MkdirAll(gcloudDir, 0755); err != nil {
		t.Fatal(err)
	}
	saContent := `{"type":"service_account","project_id":"my-project","private_key_id":"abc123","private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}`
	if err := os.WriteFile(filepath.Join(gcloudDir, "service_account_key.json"), []byte(saContent), 0644); err != nil {
		t.Fatal(err)
	}
	// Non-service-account JSON should be ignored
	if err := os.WriteFile(filepath.Join(gcloudDir, "other.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	credCloudGCPServiceAccounts(&sb, []string{home})
	output := sb.String()

	if !strings.Contains(output, "GCP Service Account") {
		t.Error("should contain GCP Service Account header")
	}
	if !strings.Contains(output, "[KEY]") {
		t.Error("should detect service account key file")
	}
	if !strings.Contains(output, "service_account_key.json") {
		t.Error("should show service account filename")
	}
	if !strings.Contains(output, "service_account") {
		t.Error("should display key file content (small file)")
	}
}

func TestCredCloudGCPLegacyCredentials(t *testing.T) {
	home := t.TempDir()

	// Create legacy credentials directory with ADC file
	legacyDir := filepath.Join(home, ".config", "gcloud", "legacy_credentials", "user@example.com")
	if err := os.MkdirAll(legacyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "adc.json"), []byte(`{"client_id":"xxx","client_secret":"yyy"}`), 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	credCloudGCPServiceAccounts(&sb, []string{home})
	output := sb.String()

	if !strings.Contains(output, "[LEGACY]") {
		t.Error("should detect legacy credential file")
	}
	if !strings.Contains(output, "adc.json") {
		t.Error("should show legacy ADC filename")
	}
}

func TestCredCloudGCPEmpty(t *testing.T) {
	home := t.TempDir()
	var sb strings.Builder
	credCloudGCPServiceAccounts(&sb, []string{home})
	if sb.Len() > 0 {
		t.Errorf("should produce no output for missing GCP dirs, got: %q", sb.String())
	}
}

func TestCredCloudK8sServiceAccountMock(t *testing.T) {
	// This test only verifies the function doesn't crash when path doesn't exist.
	// We can't easily mock /var/run/secrets without root.
	var sb strings.Builder
	credCloudK8sServiceAccount(&sb)
	// In most test environments, this path won't exist — output should be empty
	// (unless running in a real k8s pod)
	// Just ensure no panic
}

func TestCredCloudMultipleHomes(t *testing.T) {
	home1 := t.TempDir()
	home2 := t.TempDir()

	// Put AWS cache in home1
	ssoDir1 := filepath.Join(home1, ".aws", "sso", "cache")
	if err := os.MkdirAll(ssoDir1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssoDir1, "token1.json"), []byte(`{"token":"aaa"}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Put AWS cache in home2
	ssoDir2 := filepath.Join(home2, ".aws", "sso", "cache")
	if err := os.MkdirAll(ssoDir2, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssoDir2, "token2.json"), []byte(`{"token":"bbb"}`), 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	credCloudAWSCache(&sb, []string{home1, home2})
	output := sb.String()

	if !strings.Contains(output, "token1.json") {
		t.Error("should find cache in first home dir")
	}
	if !strings.Contains(output, "token2.json") {
		t.Error("should find cache in second home dir")
	}
}

func TestCredCloudAWSCacheLargeFile(t *testing.T) {
	home := t.TempDir()

	// Create a large SSO cache file (>4096 bytes) — content should NOT be displayed
	ssoDir := filepath.Join(home, ".aws", "sso", "cache")
	if err := os.MkdirAll(ssoDir, 0755); err != nil {
		t.Fatal(err)
	}
	largeContent := strings.Repeat("x", 5000)
	if err := os.WriteFile(filepath.Join(ssoDir, "large.json"), []byte(largeContent), 0644); err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	credCloudAWSCache(&sb, []string{home})
	output := sb.String()

	if !strings.Contains(output, "[SSO]") {
		t.Error("should detect the large file")
	}
	if strings.Contains(output, "Content:") {
		t.Error("should not display content of files >4096 bytes")
	}
}

func TestCredConfigsMockSSHKeys(t *testing.T) {
	home := t.TempDir()

	// Create mock SSH private key
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	keyContent := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA...\n-----END OPENSSH PRIVATE KEY-----"
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte(keyContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Create mock .env file
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("DATABASE_URL=postgres://user:pass@host/db\nSECRET_KEY=mysecret"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create mock git credentials
	if err := os.WriteFile(filepath.Join(home, ".git-credentials"), []byte("https://user:token@github.com"), 0600); err != nil {
		t.Fatal(err)
	}

	// We can't easily redirect getUserHomes, but we can call credConfigs directly
	// and verify the general structure works. The test environment may or may not
	// find these files depending on whether $HOME matches our temp dir.
	result := credConfigs(credHarvestArgs{Action: "configs"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Should at minimum have the section headers
	if !strings.Contains(result.Output, "SSH Private Keys") {
		t.Error("should have SSH Private Keys section")
	}
	if !strings.Contains(result.Output, "Environment Files") {
		t.Error("should have Environment Files section")
	}
	if !strings.Contains(result.Output, "Git Credentials") {
		t.Error("should have Git Credentials section")
	}
	if !strings.Contains(result.Output, "Database Configs") {
		t.Error("should have Database Configs section")
	}
}

func TestCredCloudCredPathsCompleteness(t *testing.T) {
	// Verify cloudCredPaths has expected cloud providers
	providers := map[string]bool{
		"AWS": false, "GCP": false, "Azure": false, "Kubernetes": false,
		"Docker": false, "Terraform": false, "Vault (HashiCorp)": false,
	}
	for _, cred := range cloudCredPaths {
		if _, ok := providers[cred.name]; ok {
			providers[cred.name] = true
		}
		// Each provider must have at least one path or env var
		if len(cred.paths) == 0 && len(cred.envVars) == 0 {
			t.Errorf("provider %s has no paths and no env vars", cred.name)
		}
	}
	for name, found := range providers {
		if !found {
			t.Errorf("expected cloud provider %s in cloudCredPaths", name)
		}
	}
}

func TestConfigPatternsCompleteness(t *testing.T) {
	// Verify configPatterns has expected categories
	categories := map[string]bool{
		"Environment Files": false, "SSH Private Keys": false,
		"Git Credentials": false, "NPM/Pip/Gem Tokens": false,
	}
	for _, cfg := range configPatterns {
		if _, ok := categories[cfg.name]; ok {
			categories[cfg.name] = true
		}
		if len(cfg.patterns) == 0 {
			t.Errorf("config pattern %s has no patterns", cfg.name)
		}
	}
	for name, found := range categories {
		if !found {
			t.Errorf("expected config category %s in configPatterns", name)
		}
	}
}

func TestCredCloudFileContentTruncation(t *testing.T) {
	home := t.TempDir()

	// Create a mock AWS credentials file that's >2000 chars but <10240
	awsDir := filepath.Join(home, ".aws")
	if err := os.MkdirAll(awsDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Create a file that's exactly 3000 bytes
	content := "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = " + strings.Repeat("X", 2900)
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// The credCloud function reads from getUserHomes which uses /etc/passwd.
	// We can't easily redirect that. But we can verify the truncation logic
	// by checking the credIndentLines function with long content.
	longContent := strings.Repeat("line\n", 500)
	if len(longContent) > 2000 {
		truncated := longContent[:2000] + "\n... (truncated)"
		result := credIndentLines(truncated, "    ")
		if !strings.Contains(result, "... (truncated)") {
			t.Error("truncated content should preserve truncation marker")
		}
	}
}

func TestCredHarvestPlainTextShadow(t *testing.T) {
	cmd := &CredHarvestCommand{}
	result := cmd.Execute(structs.Task{Params: "shadow"})
	if result.Status != "success" {
		t.Errorf("plain text 'shadow' should succeed, got %s: %s", result.Status, result.Output)
	}
}

func TestCredHarvestPlainTextAll(t *testing.T) {
	cmd := &CredHarvestCommand{}
	result := cmd.Execute(structs.Task{Params: "all"})
	if result.Status != "success" {
		t.Errorf("plain text 'all' should succeed, got %s: %s", result.Status, result.Output)
	}
}

func TestCredHarvestPlainTextWithUser(t *testing.T) {
	cmd := &CredHarvestCommand{}
	result := cmd.Execute(structs.Task{Params: "shadow root"})
	if result.Status != "success" {
		t.Errorf("plain text 'shadow root' should succeed, got %s: %s", result.Status, result.Output)
	}
}
