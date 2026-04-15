package commands

import (
	"strings"
	"testing"
)

func TestParseZshHistory_ExtendedFormat(t *testing.T) {
	data := []byte(`: 1617000000:0;sshpass -p 'secret123' ssh user@host
: 1617000001:0;ls -la
: 1617000002:0;curl -u admin:pass123 https://example.com
`)
	lines := parseZshHistory(data)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "sshpass") {
		t.Errorf("expected first line to contain sshpass, got: %s", lines[0])
	}
	if !strings.Contains(lines[2], "curl") {
		t.Errorf("expected third line to contain curl, got: %s", lines[2])
	}
}

func TestParseZshHistory_PlainFormat(t *testing.T) {
	// Zsh without extended_history option
	data := []byte("ls -la\ncd /tmp\npwd\n")
	lines := parseZshHistory(data)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "ls -la" {
		t.Errorf("unexpected line: %s", lines[0])
	}
}

func TestParseZshHistory_EmptyLines(t *testing.T) {
	data := []byte("\n\n: 1617000000:0;whoami\n\n")
	lines := parseZshHistory(data)
	if len(lines) != 1 {
		t.Fatalf("expected 1 non-empty line, got %d", len(lines))
	}
}

func TestParseFishHistory_Standard(t *testing.T) {
	data := []byte(`- cmd: sshpass -p mysecret ssh root@server
  when: 1617000000
- cmd: ls -la
  when: 1617000001
`)
	lines := parseFishHistory(data)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "sshpass") {
		t.Errorf("expected sshpass in first line, got: %s", lines[0])
	}
	if lines[1] != "ls -la" {
		t.Errorf("expected 'ls -la', got: %s", lines[1])
	}
}

func TestParseFishHistory_EmptyInput(t *testing.T) {
	lines := parseFishHistory([]byte(""))
	if len(lines) != 0 {
		t.Errorf("expected 0 lines, got %d", len(lines))
	}
}

func TestScanHistoryLines_SSHPass(t *testing.T) {
	lines := []string{
		"sshpass -p 'mysecretpass' ssh user@host",
		"ls -la",
	}
	findings := scanHistoryLines(lines, "Bash", "/home/user/.bash_history")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "SSH Password (sshpass)" {
		t.Errorf("unexpected category: %s", findings[0].Category)
	}
	if findings[0].Value != "mysecretpass" {
		t.Errorf("unexpected value: %s", findings[0].Value)
	}
}

func TestScanHistoryLines_MySQLPassword(t *testing.T) {
	lines := []string{
		"mysql -u root -pS3cret database",
		"mysql --password=hunter2 -u admin",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestScanHistoryLines_CurlCredentials(t *testing.T) {
	lines := []string{
		"curl -u admin:password123 https://api.example.com/data",
		"curl --user test:secret https://example.com",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Category != "HTTP Credential (curl)" {
			t.Errorf("unexpected category: %s", f.Category)
		}
		if !strings.Contains(f.Value, ":") {
			t.Errorf("expected user:pass format, got: %s", f.Value)
		}
	}
}

func TestScanHistoryLines_WgetPassword(t *testing.T) {
	lines := []string{
		"wget --password=s3cret https://example.com/file.zip",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Value != "s3cret" {
		t.Errorf("unexpected value: %s", findings[0].Value)
	}
}

func TestScanHistoryLines_DockerLoginPassword(t *testing.T) {
	lines := []string{
		"docker login --password=mytoken registry.example.com",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "Docker Registry Password" {
		t.Errorf("unexpected category: %s", findings[0].Category)
	}
}

func TestScanHistoryLines_ExportedSecret(t *testing.T) {
	lines := []string{
		"export API_KEY=sk-1234567890abcdef",
		"export PATH=/usr/bin:/bin",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	// Only the API_KEY line should match (contains "key" sensitive keyword)
	found := false
	for _, f := range findings {
		if f.Category == "Exported Secret" {
			found = true
			if !strings.Contains(f.Value, "API_KEY") {
				t.Errorf("unexpected value: %s", f.Value)
			}
		}
	}
	if !found {
		t.Error("expected to find exported secret")
	}
}

func TestScanHistoryLines_GitToken(t *testing.T) {
	lines := []string{
		"git clone https://ghp_abc123token@github.com/user/repo.git",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "Git Token" {
		t.Errorf("unexpected category: %s", findings[0].Category)
	}
}

func TestScanHistoryLines_SudoEchoPipe(t *testing.T) {
	lines := []string{
		"echo 'mypassword' | sudo -S apt install vim",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "Sudo Password (echo pipe)" {
		t.Errorf("unexpected category: %s", findings[0].Category)
	}
	if findings[0].Value != "mypassword" {
		t.Errorf("unexpected value: %s", findings[0].Value)
	}
}

func TestScanHistoryLines_Deduplication(t *testing.T) {
	// Same command repeated should only produce one finding
	lines := []string{
		"sshpass -p secret ssh user@host",
		"sshpass -p secret ssh user@host",
		"sshpass -p secret ssh user@host",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

func TestScanHistoryLines_NoMatches(t *testing.T) {
	lines := []string{
		"ls -la",
		"cd /tmp",
		"cat README.md",
		"make build",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for benign commands, got %d", len(findings))
	}
}

func TestScanHistoryLines_PostgreSQL(t *testing.T) {
	lines := []string{
		"psql postgres://dbuser:dbpass@localhost/mydb",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "PostgreSQL Credential" {
		t.Errorf("unexpected category: %s", findings[0].Category)
	}
	if findings[0].Value != "dbuser:dbpass" {
		t.Errorf("unexpected value: %s", findings[0].Value)
	}
}

func TestScanHistoryLines_HtpasswdPassword(t *testing.T) {
	lines := []string{
		"htpasswd -b /etc/htpasswd admin supersecret",
	}
	findings := scanHistoryLines(lines, "Bash", ".bash_history")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Value != "supersecret" {
		t.Errorf("unexpected value: %s", findings[0].Value)
	}
}

func TestScanHistoryLines_EmptyInput(t *testing.T) {
	findings := scanHistoryLines(nil, "Bash", ".bash_history")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil input, got %d", len(findings))
	}
}
