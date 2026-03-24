package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSecretScanCommand_Name(t *testing.T) {
	cmd := &SecretScanCommand{}
	if cmd.Name() != "secret-scan" {
		t.Errorf("expected 'secret-scan', got %q", cmd.Name())
	}
}

func TestSecretScanCommand_Description(t *testing.T) {
	cmd := &SecretScanCommand{}
	if !strings.Contains(cmd.Description(), "T1552") {
		t.Error("expected MITRE ATT&CK ID in description")
	}
}

func TestSecretScanCommand_Registration(t *testing.T) {
	Initialize()
	cmd := GetCommand("secret-scan")
	if cmd == nil {
		t.Fatal("secret-scan command not registered")
	}
}

// --- Pattern Matching Tests ---

func TestScanFileForSecrets_AWSKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config.env")
	os.WriteFile(f, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find AWS key")
	}
	if results[0].Type != "AWS Access Key" {
		t.Errorf("type = %q, want 'AWS Access Key'", results[0].Type)
	}
	if results[0].Line != 1 {
		t.Errorf("line = %d, want 1", results[0].Line)
	}
}

func TestScanFileForSecrets_PrivateKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "id_rsa")
	os.WriteFile(f, []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find private key header")
	}
	if results[0].Type != "Private Key" {
		t.Errorf("type = %q, want 'Private Key'", results[0].Type)
	}
}

func TestScanFileForSecrets_GitHubToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".env")
	os.WriteFile(f, []byte("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find GitHub token")
	}
	if results[0].Type != "GitHub Token" {
		t.Errorf("type = %q, want 'GitHub Token'", results[0].Type)
	}
}

func TestScanFileForSecrets_ConnectionString(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yml")
	os.WriteFile(f, []byte("database_url: postgresql://user:secret@db.example.com:5432/mydb\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find connection string")
	}
	if results[0].Type != "Connection String" {
		t.Errorf("type = %q, want 'Connection String'", results[0].Type)
	}
}

func TestScanFileForSecrets_GenericPassword(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "settings.conf")
	os.WriteFile(f, []byte("password = MySuperSecretPassword123!\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find generic password")
	}
}

func TestScanFileForSecrets_NoSecrets(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "readme.txt")
	os.WriteFile(f, []byte("This is a normal file with no secrets.\nJust some regular text.\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestScanFileForSecrets_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.env")
	os.WriteFile(f, []byte(""), 0644)

	results := scanFileForSecrets(f)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty file, got %d", len(results))
	}
}

func TestScanFileForSecrets_SlackToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config.json")
	// Build the token dynamically to avoid GitHub push protection
	token := "xo" + "xb" + "-0000000000-0000000000000-TESTtestTESTtestTESTtest"
	os.WriteFile(f, []byte(fmt.Sprintf(`{"token": "%s"}`, token)+"\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Slack token")
	}
	if results[0].Type != "Slack Token" {
		t.Errorf("type = %q, want 'Slack Token'", results[0].Type)
	}
}

func TestScanFileForSecrets_StripeKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".env")
	// Build the key dynamically to avoid GitHub push protection
	key := "sk" + "_test_" + "00000000000000000000"
	os.WriteFile(f, []byte(fmt.Sprintf("STRIPE_KEY=%s\n", key)), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Stripe key")
	}
	if results[0].Type != "Stripe Key" {
		t.Errorf("type = %q, want 'Stripe Key'", results[0].Type)
	}
}

// --- Redaction Tests ---

func TestRedactSecret_AWSKey(t *testing.T) {
	result := redactSecret("AKIAIOSFODNN7EXAMPLE", "AWS Access Key")
	if !strings.Contains(result, "***") {
		t.Errorf("expected redaction, got %q", result)
	}
	if strings.Contains(result, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("full key should not appear in redacted output")
	}
}

func TestRedactSecret_PrivateKey(t *testing.T) {
	result := redactSecret("-----BEGIN RSA PRIVATE KEY-----", "Private Key")
	if result != "-----BEGIN RSA PRIVATE KEY-----" {
		t.Errorf("private key header should not be redacted, got %q", result)
	}
}

func TestRedactSecret_GenericPassword(t *testing.T) {
	result := redactSecret("password = SuperSecret123!", "Generic Password")
	if !strings.Contains(result, "[REDACTED]") {
		t.Errorf("expected [REDACTED], got %q", result)
	}
}

func TestRedactSecret_ConnectionString(t *testing.T) {
	result := redactSecret("postgresql://user:mypassword@db.example.com/prod", "Connection String")
	if strings.Contains(result, "mypassword") {
		t.Error("password should be masked in connection string")
	}
	if !strings.Contains(result, "***") {
		t.Errorf("expected *** in redacted connection string, got %q", result)
	}
}

// --- Integration Test ---

func TestSecretScanCommand_Execute(t *testing.T) {
	dir := t.TempDir()
	// Create a test file with a known secret
	envFile := filepath.Join(dir, ".env")
	os.WriteFile(envFile, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nNORMAL_VAR=hello\n"), 0644)

	// Create a subdirectory with another secret
	subDir := filepath.Join(dir, "config")
	os.MkdirAll(subDir, 0755)
	stripeKey := "sk" + "_test_" + "00000000000000000000"
	os.WriteFile(filepath.Join(subDir, "app.yml"), []byte(fmt.Sprintf("secret_key: %s\n", stripeKey)), 0644)

	cmd := &SecretScanCommand{}
	params, _ := json.Marshal(secretScanArgs{
		Path:       dir,
		Depth:      3,
		MaxResults: 50,
	})

	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "AWS Access Key") {
		t.Error("expected AWS Access Key finding in output")
	}
	if !strings.Contains(result.Output, "Stripe Key") {
		t.Error("expected Stripe Key finding in output")
	}
}

func TestSecretScanCommand_MaxResults(t *testing.T) {
	dir := t.TempDir()
	// Create file with many secrets
	var content strings.Builder
	for i := 0; i < 20; i++ {
		content.WriteString("password = secret" + strings.Repeat("x", 10) + "\n")
	}
	os.WriteFile(filepath.Join(dir, "config.env"), []byte(content.String()), 0644)

	cmd := &SecretScanCommand{}
	params, _ := json.Marshal(secretScanArgs{
		Path:       dir,
		MaxResults: 5,
	})

	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "truncated") {
		t.Error("expected truncation notice when max_results reached")
	}
}

func TestScanFileForSecrets_VaultToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "vault.env")
	os.WriteFile(f, []byte("VAULT_TOKEN=hvs.CAESIIG1z2Bq4NzHNO6WfPHkIuBBBBBB\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Vault token")
	}
	if results[0].Type != "HashiCorp Vault Token" {
		t.Errorf("type = %q, want 'HashiCorp Vault Token'", results[0].Type)
	}
}

func TestScanFileForSecrets_DigitalOceanToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "do.env")
	os.WriteFile(f, []byte("DO_TOKEN=dop_v1_"+strings.Repeat("a1b2c3d4", 8)+"\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find DigitalOcean token")
	}
	if results[0].Type != "DigitalOcean Token" {
		t.Errorf("type = %q, want 'DigitalOcean Token'", results[0].Type)
	}
}

func TestScanFileForSecrets_ShopifyToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "shopify.env")
	os.WriteFile(f, []byte("SHOPIFY_TOKEN=shpat_"+strings.Repeat("a1b2c3d4", 4)+"\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Shopify token")
	}
	if results[0].Type != "Shopify Token" {
		t.Errorf("type = %q, want 'Shopify Token'", results[0].Type)
	}
}

func TestScanFileForSecrets_DatabricksToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "databricks.env")
	os.WriteFile(f, []byte("DB_TOKEN=dapi"+strings.Repeat("ab12cd34", 4)+"\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Databricks token")
	}
	if results[0].Type != "Databricks Token" {
		t.Errorf("type = %q, want 'Databricks Token'", results[0].Type)
	}
}

func TestSecretPatternsCompile(t *testing.T) {
	// Verify all patterns compiled successfully
	if len(secretPatterns) < 33 {
		t.Errorf("expected at least 33 secret patterns, got %d", len(secretPatterns))
	}
	for _, p := range secretPatterns {
		if p.Name == "" {
			t.Error("pattern has empty name")
		}
		if p.Pattern == nil {
			t.Errorf("pattern %q has nil regex", p.Name)
		}
	}
}

func TestScanFileForSecrets_GoogleAPIKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "gcp.env")
	// AIza + 35 alphanumeric chars = 39 total
	os.WriteFile(f, []byte("credential=AIzaSyA01234567890123456789012345678ABC\n"), 0644)

	results := scanFileForSecrets(f)
	found := false
	for _, r := range results {
		if r.Type == "Google API Key" {
			found = true
			break
		}
	}
	if !found {
		types := make([]string, len(results))
		for i, r := range results {
			types[i] = r.Type
		}
		t.Errorf("expected to find Google API Key in results, got types: %v", types)
	}
}

func TestScanFileForSecrets_TelegramBotToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bot.conf")
	// Pattern: [0-9]{8,10}:AA[0-9A-Za-z_-]{33}
	// 1234567890 (10 digits) : AA + 33 alphanumeric chars
	os.WriteFile(f, []byte("BOT_TOKEN=1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaBx\n"), 0644)

	results := scanFileForSecrets(f)
	found := false
	for _, r := range results {
		if r.Type == "Telegram Bot Token" {
			found = true
			break
		}
	}
	if !found {
		types := make([]string, len(results))
		for i, r := range results {
			types[i] = r.Type
		}
		t.Errorf("expected to find Telegram Bot Token in results, got types: %v", types)
	}
}

func TestScanFileForSecrets_MailgunKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "mail.env")
	os.WriteFile(f, []byte("MAILGUN_KEY=key-"+strings.Repeat("a1b2c3d4", 4)+"\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Mailgun API Key")
	}
	if results[0].Type != "Mailgun API Key" {
		t.Errorf("type = %q, want 'Mailgun API Key'", results[0].Type)
	}
}

func TestScanFileForSecrets_SquareToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "square.env")
	os.WriteFile(f, []byte("SQUARE_TOKEN=sq0atp-"+strings.Repeat("AbCd", 6)+"\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Square Access Token")
	}
	if results[0].Type != "Square Access Token" {
		t.Errorf("type = %q, want 'Square Access Token'", results[0].Type)
	}
}

func TestScanFileForSecrets_AWSStsToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "aws.env")
	os.WriteFile(f, []byte("AWS_ACCESS_KEY_ID=ASIAQWERTYUIOP123456\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find AWS STS Session Token")
	}
	if results[0].Type != "AWS STS Session Token" {
		t.Errorf("type = %q, want 'AWS STS Session Token'", results[0].Type)
	}
}

func TestScanFileForSecrets_NewRelicKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "nr.env")
	// Build key dynamically to avoid push protection false positive
	prefix := "NRAK-"
	suffix := strings.Repeat("A1B2C3D", 4)[:27] // 27 alphanumeric chars
	os.WriteFile(f, []byte("KEY="+prefix+suffix+"\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find New Relic API Key")
	}
	if results[0].Type != "New Relic API Key" {
		t.Errorf("type = %q, want 'New Relic API Key'", results[0].Type)
	}
}

func TestScanFileForSecrets_PagerDutyToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "pd.env")
	os.WriteFile(f, []byte(fmt.Sprintf("PD_TOKEN=pdt_%s\n", strings.Repeat("abcDEF12", 4))), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find PagerDuty API Token")
	}
	if results[0].Type != "PagerDuty API Token" {
		t.Errorf("type = %q, want 'PagerDuty API Token'", results[0].Type)
	}
}

func TestScanFileForSecrets_SentryDSN(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "sentry.env")
	os.WriteFile(f, []byte("SENTRY_DSN=https://abcdef0123456789abcdef0123456789@o12345.ingest.sentry.io/6789012\n"), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Sentry DSN")
	}
	if results[0].Type != "Sentry DSN" {
		t.Errorf("type = %q, want 'Sentry DSN'", results[0].Type)
	}
}

func TestScanFileForSecrets_DatadogKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "dd.env")
	// Use dd_app_key format to avoid matching the generic api_key pattern first
	os.WriteFile(f, []byte(fmt.Sprintf("dd_app_key=%s\n", strings.Repeat("abcdef01", 4))), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find Datadog API Key")
	}
	if results[0].Type != "Datadog API Key" {
		t.Errorf("type = %q, want 'Datadog API Key'", results[0].Type)
	}
}

func TestScanFileForSecrets_CircleCIToken(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ci.env")
	os.WriteFile(f, []byte(fmt.Sprintf("circle-token=%s\n", strings.Repeat("abcdef01", 5))), 0644)

	results := scanFileForSecrets(f)
	if len(results) == 0 {
		t.Fatal("expected to find CircleCI Token")
	}
	if results[0].Type != "CircleCI Token" {
		t.Errorf("type = %q, want 'CircleCI Token'", results[0].Type)
	}
}

func TestSecretPatternCount(t *testing.T) {
	// Verify we have the expected number of patterns (35 + 7 = 42)
	if len(secretPatterns) != 42 {
		t.Errorf("expected 42 secret patterns, got %d", len(secretPatterns))
	}
}

func TestSecretScanCommand_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	cmd := &SecretScanCommand{}
	params, _ := json.Marshal(secretScanArgs{Path: dir})

	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "No secrets found") {
		t.Errorf("expected 'No secrets found', got %q", result.Output)
	}
}
