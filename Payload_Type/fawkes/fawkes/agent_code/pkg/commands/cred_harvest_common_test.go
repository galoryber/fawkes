package commands

import (
	"strings"
	"testing"
)

// --- extractQuotedOrWord ---

func TestExtractQuotedOrWord(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"single_quoted", "'password123' rest", "password123"},
		{"double_quoted", `"secret" rest`, "secret"},
		{"unquoted_word", "mypassword --next", "mypassword"},
		{"unquoted_single", "token", "token"},
		{"empty", "", ""},
		{"spaces_only", "   ", ""},
		{"quoted_empty", "'' rest", ""},
		{"quoted_with_spaces", "'my password' rest", "my password"},
		{"leading_spaces", "  word rest", "word"},
		{"tab_separated", "word\tnext", "word"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractQuotedOrWord(tt.input)
			if got != tt.want {
				t.Errorf("extractQuotedOrWord(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- parseZshHistory ---

func TestParseZshHistory(t *testing.T) {
	input := `: 1234567890:0;ls -la
: 1234567891:0;export SECRET_KEY=abc123
plain command
`
	lines := parseZshHistory([]byte(input))
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "ls -la" {
		t.Errorf("line 0 = %q, want %q", lines[0], "ls -la")
	}
	if lines[1] != "export SECRET_KEY=abc123" {
		t.Errorf("line 1 = %q, want %q", lines[1], "export SECRET_KEY=abc123")
	}
	if lines[2] != "plain command" {
		t.Errorf("line 2 = %q, want %q", lines[2], "plain command")
	}
}

func TestParseZshHistory_Empty(t *testing.T) {
	lines := parseZshHistory([]byte(""))
	if len(lines) != 0 {
		t.Errorf("expected 0 lines, got %d", len(lines))
	}
}

// --- parseFishHistory ---

func TestParseFishHistory(t *testing.T) {
	input := `- cmd: ssh user@host
  when: 1234567890
- cmd: export API_KEY=secret
  when: 1234567891
`
	lines := parseFishHistory([]byte(input))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "ssh user@host" {
		t.Errorf("line 0 = %q", lines[0])
	}
	if lines[1] != "export API_KEY=secret" {
		t.Errorf("line 1 = %q", lines[1])
	}
}

func TestParseFishHistory_Empty(t *testing.T) {
	lines := parseFishHistory([]byte(""))
	if len(lines) != 0 {
		t.Errorf("expected 0 lines, got %d", len(lines))
	}
}

// --- scanHistoryLines (pattern matching) ---

func TestScanHistoryLines_Sshpass(t *testing.T) {
	lines := []string{
		"sshpass -p 'mypassword' ssh user@host",
		"sshpass -p secret123 ssh root@10.0.0.1",
		"sshpass -p \"quoted pass\" ssh admin@box",
	}
	findings := scanHistoryLines(lines, "Bash", "/home/test/.bash_history")
	if len(findings) != 3 {
		t.Fatalf("expected 3 sshpass findings, got %d", len(findings))
	}
	if findings[0].Value != "mypassword" {
		t.Errorf("finding[0].Value = %q, want %q", findings[0].Value, "mypassword")
	}
	if findings[1].Value != "secret123" {
		t.Errorf("finding[1].Value = %q, want %q", findings[1].Value, "secret123")
	}
	if findings[2].Value != "quoted pass" {
		t.Errorf("finding[2].Value = %q, want %q", findings[2].Value, "quoted pass")
	}
	if findings[0].Category != "SSH Password (sshpass)" {
		t.Errorf("category = %q", findings[0].Category)
	}
}

func TestScanHistoryLines_MySQL(t *testing.T) {
	lines := []string{
		"mysql -u root -pSECRET123 mydb",
		"mysql --password=hunter2 -u admin",
		"mysql -u user -p",     // interactive prompt, should NOT match
		"mysql -u user -p -h x", // -p followed by space+flag, should NOT match
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 2 {
		t.Fatalf("expected 2 mysql findings (interactive excluded), got %d", len(findings))
	}
	if findings[0].Value != "SECRET123" {
		t.Errorf("finding[0].Value = %q, want %q", findings[0].Value, "SECRET123")
	}
	if findings[1].Value != "hunter2" {
		t.Errorf("finding[1].Value = %q, want %q", findings[1].Value, "hunter2")
	}
}

func TestScanHistoryLines_Curl(t *testing.T) {
	lines := []string{
		"curl -u admin:password123 https://api.example.com",
		"curl --user root:topsecret http://localhost",
		`curl -H "Authorization: Bearer eyJtoken123" https://api.example.com`,
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 3 {
		t.Fatalf("expected 3 curl findings, got %d", len(findings))
	}
	if findings[0].Value != "admin:password123" {
		t.Errorf("finding[0].Value = %q", findings[0].Value)
	}
	if findings[1].Value != "root:topsecret" {
		t.Errorf("finding[1].Value = %q", findings[1].Value)
	}
	if !strings.Contains(findings[2].Value, "Bearer") {
		t.Errorf("finding[2].Value = %q, should contain Bearer", findings[2].Value)
	}
}

func TestScanHistoryLines_Wget(t *testing.T) {
	lines := []string{
		"wget --password=secret123 ftp://server/file",
		"wget --http-password=httppass http://host/path",
		"wget --ftp-password=ftppass ftp://host/file",
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 3 {
		t.Fatalf("expected 3 wget findings, got %d", len(findings))
	}
	if findings[0].Value != "secret123" {
		t.Errorf("finding[0].Value = %q", findings[0].Value)
	}
}

func TestScanHistoryLines_DockerLogin(t *testing.T) {
	lines := []string{
		"docker login -p mysecret registry.example.com",
		"docker login --password=dkr_pat_abcdef registry.io",
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 2 {
		t.Fatalf("expected 2 docker findings, got %d", len(findings))
	}
	if findings[0].Value != "mysecret" {
		t.Errorf("finding[0].Value = %q", findings[0].Value)
	}
}

func TestScanHistoryLines_Export(t *testing.T) {
	lines := []string{
		"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"export PASSWORD=hunter2",
		"export PATH=/usr/bin:/bin",         // not sensitive
		"export HOME=/home/user",            // not sensitive
		"export API_KEY=abcdef123456",
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 3 {
		t.Fatalf("expected 3 export findings (PATH/HOME excluded), got %d", len(findings))
	}
	for _, f := range findings {
		if f.Category != "Exported Secret" {
			t.Errorf("unexpected category: %q", f.Category)
		}
	}
}

func TestScanHistoryLines_GitClone(t *testing.T) {
	lines := []string{
		"git clone https://ghp_abc123def456@github.com/user/repo.git",
		"git clone https://user:token123@gitlab.com/user/repo.git",
		"git clone git@github.com:user/repo.git",  // SSH, should NOT match
		"git clone https://github.com/user/repo.git", // no token, should NOT match
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 2 {
		t.Fatalf("expected 2 git clone findings, got %d", len(findings))
	}
	if findings[0].Value != "ghp_abc123def456" {
		t.Errorf("finding[0].Value = %q", findings[0].Value)
	}
}

func TestScanHistoryLines_Psql(t *testing.T) {
	lines := []string{
		"psql postgres://admin:dbpass@localhost:5432/mydb",
		"psql -h localhost mydb",  // no inline cred
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 1 {
		t.Fatalf("expected 1 psql finding, got %d", len(findings))
	}
	if findings[0].Value != "admin:dbpass" {
		t.Errorf("finding[0].Value = %q", findings[0].Value)
	}
}

func TestScanHistoryLines_Htpasswd(t *testing.T) {
	lines := []string{
		"htpasswd -b /etc/nginx/.htpasswd admin secretpass",
		"htpasswd -B /etc/apache/.htpasswd user p@ss!",
		"htpasswd /etc/.htpasswd user", // no -b, interactive
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 2 {
		t.Fatalf("expected 2 htpasswd findings, got %d", len(findings))
	}
	if findings[0].Value != "secretpass" {
		t.Errorf("finding[0].Value = %q", findings[0].Value)
	}
}

func TestScanHistoryLines_SudoPipe(t *testing.T) {
	lines := []string{
		"echo 'mypassword' | sudo -S apt update",
		"echo secret123 | sudo -S mount /dev/sda1 /mnt",
		"sudo apt update",  // no echo pipe, should NOT match
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 2 {
		t.Fatalf("expected 2 sudo pipe findings, got %d", len(findings))
	}
	if findings[0].Value != "mypassword" {
		t.Errorf("finding[0].Value = %q", findings[0].Value)
	}
}

func TestScanHistoryLines_Dedup(t *testing.T) {
	// Same command repeated should only produce one finding
	lines := []string{
		"sshpass -p 'same_password' ssh user@host",
		"sshpass -p 'same_password' ssh user@host",
		"sshpass -p 'same_password' ssh user@host2",
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (deduped), got %d", len(findings))
	}
}

func TestScanHistoryLines_NoMatch(t *testing.T) {
	lines := []string{
		"ls -la",
		"cd /tmp",
		"cat /etc/hostname",
		"git status",
	}
	findings := scanHistoryLines(lines, "Bash", "test")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanHistoryLines_Empty(t *testing.T) {
	findings := scanHistoryLines(nil, "Bash", "test")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil input, got %d", len(findings))
	}
}

func TestScanHistoryLines_FindingFields(t *testing.T) {
	lines := []string{"sshpass -p secret ssh user@host"}
	findings := scanHistoryLines(lines, "Zsh", "/home/user/.zsh_history")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Shell != "Zsh" {
		t.Errorf("Shell = %q", f.Shell)
	}
	if f.File != "/home/user/.zsh_history" {
		t.Errorf("File = %q", f.File)
	}
	if f.Line != "sshpass -p secret ssh user@host" {
		t.Errorf("Line = %q", f.Line)
	}
	if f.Category != "SSH Password (sshpass)" {
		t.Errorf("Category = %q", f.Category)
	}
	if f.Value != "secret" {
		t.Errorf("Value = %q", f.Value)
	}
}

// --- credIndentLines ---

func TestCredIndentLines_Basic(t *testing.T) {
	result := credIndentLines("line1\nline2\nline3", "  ")
	lines := strings.Split(result, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("line %d not indented: %q", i, line)
		}
	}
}

func TestCredIndentLines_Empty(t *testing.T) {
	result := credIndentLines("", "    ")
	if result != "" {
		t.Errorf("expected empty string for empty input, got %q", result)
	}
}

func TestCredIndentLines_EmptyLines(t *testing.T) {
	result := credIndentLines("line1\n\nline3", ">>")
	lines := strings.Split(result, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	// Empty lines should NOT be indented
	if lines[1] != "" {
		t.Errorf("empty line should stay empty, got %q", lines[1])
	}
	if !strings.HasPrefix(lines[0], ">>") {
		t.Errorf("non-empty line should be indented: %q", lines[0])
	}
}

func TestCredIndentLines_SingleLine(t *testing.T) {
	result := credIndentLines("hello", "    ")
	if result != "    hello" {
		t.Errorf("expected '    hello', got %q", result)
	}
}

func TestCredIndentLines_DifferentPrefixes(t *testing.T) {
	tests := []struct {
		prefix string
	}{
		{"  "},
		{"    "},
		{"\t"},
		{"| "},
	}
	for _, tc := range tests {
		result := credIndentLines("test", tc.prefix)
		if !strings.HasPrefix(result, tc.prefix) {
			t.Errorf("expected prefix %q, got %q", tc.prefix, result)
		}
	}
}
