//go:build linux

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// privescCheckCronScripts checks for cron jobs that reference scripts writable by the current user.
// If a cron job runs as root and calls a script we can write to, we can inject commands.
func privescCheckCronScripts() structs.CommandResult {
	var sb strings.Builder
	var findings []string

	// Parse cron sources for script references
	cronSources := []struct {
		path string
		desc string
	}{
		{"/etc/crontab", "/etc/crontab"},
	}

	// Add /etc/cron.d/ files
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
				cronSources = append(cronSources, struct {
					path string
					desc string
				}{filepath.Join("/etc/cron.d", entry.Name()), "cron.d/" + entry.Name()})
			}
		}
	}

	for _, cs := range cronSources {
		data, err := os.ReadFile(cs.path)
		if err != nil {
			continue
		}
		defer structs.ZeroBytes(data) // opsec: clear cron config (may contain embedded secrets)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Extract potential script paths from cron lines
			scripts := extractScriptPaths(line)
			for _, script := range scripts {
				if isWritable(filepath.Dir(script)) || isWritableFile(script) {
					findings = append(findings, fmt.Sprintf("  [!] %s references writable: %s", cs.desc, script))
				}
			}
		}
	}

	// Check periodic cron directories for writable scripts
	periodicDirs := []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range periodicDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			script := filepath.Join(dir, entry.Name())
			if isWritableFile(script) {
				findings = append(findings, fmt.Sprintf("  [!] Writable cron script: %s", script))
			}
		}
	}

	if len(findings) > 0 {
		sb.WriteString(fmt.Sprintf("[!] Found %d writable cron scripts/targets:\n", len(findings)))
		sb.WriteString(strings.Join(findings, "\n"))
		sb.WriteString("\n[!] Modify these to inject commands that run as the cron job owner (often root)")
	} else {
		sb.WriteString("No writable cron scripts found — cron is not an escalation vector")
	}

	return successResult(sb.String())
}

// extractScriptPaths extracts file paths from a cron line that might be scripts.
func extractScriptPaths(line string) []string {
	var paths []string
	fields := strings.Fields(line)
	// Skip cron timing fields (first 5-6 fields are schedule + optional user)
	for _, field := range fields {
		if strings.HasPrefix(field, "/") && !strings.HasPrefix(field, "/dev/") {
			// Skip output redirection targets
			if strings.Contains(field, ">") {
				continue
			}
			paths = append(paths, field)
		}
	}
	return paths
}

// isWritableFile checks if a specific file can be opened for writing.
func isWritableFile(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// privescCheckNFS checks /etc/exports for NFS shares with no_root_squash.
// no_root_squash allows root on the NFS client to act as root on the server,
// enabling SUID binary deployment for privilege escalation.
func privescCheckNFS() structs.CommandResult {
	var sb strings.Builder

	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		return successResult("No /etc/exports found — NFS is not configured")
	}
	defer structs.ZeroBytes(data)

	var noSquash []string
	var allShares []string

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allShares = append(allShares, "  "+line)
		if strings.Contains(line, "no_root_squash") {
			noSquash = append(noSquash, "  [!] "+line)
		}
	}

	if len(allShares) > 0 {
		sb.WriteString(fmt.Sprintf("NFS exports (%d shares):\n", len(allShares)))
		sb.WriteString(strings.Join(allShares, "\n"))
	}

	if len(noSquash) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n[!] VULNERABLE — %d shares with no_root_squash:\n", len(noSquash)))
		sb.WriteString(strings.Join(noSquash, "\n"))
		sb.WriteString("\n[!] Mount the share, create a SUID binary as root, execute on target for root shell")
	} else if len(allShares) > 0 {
		sb.WriteString("\nAll shares use root_squash (default) — no NFS escalation vector")
	} else {
		sb.WriteString("No NFS exports configured")
	}

	return successResult(sb.String())
}

// privescCheckSystemdUnits checks for systemd service/timer files writable by the current user.
// Writable service files that run as root allow code injection.
func privescCheckSystemdUnits() structs.CommandResult {
	var sb strings.Builder
	var findings []string

	systemdDirs := []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
		"/run/systemd/system",
	}

	for _, dir := range systemdDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
				continue
			}
			path := filepath.Join(dir, name)
			if isWritableFile(path) {
				findings = append(findings, fmt.Sprintf("  [!] Writable: %s", path))
			}
		}
	}

	// Also check user-level systemd directories
	if home := os.Getenv("HOME"); home != "" {
		userDir := filepath.Join(home, ".config/systemd/user")
		if entries, err := os.ReadDir(userDir); err == nil {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".service") || strings.HasSuffix(entry.Name(), ".timer") {
					findings = append(findings, fmt.Sprintf("  [user] %s", filepath.Join(userDir, entry.Name())))
				}
			}
		}
	}

	if len(findings) > 0 {
		sb.WriteString(fmt.Sprintf("[!] Found %d writable/user systemd units:\n", len(findings)))
		sb.WriteString(strings.Join(findings, "\n"))
		sb.WriteString("\n[!] Modify ExecStart= to inject commands that run as the service user")
	} else {
		sb.WriteString("No writable systemd units found — systemd is not an escalation vector")
	}

	return successResult(sb.String())
}
