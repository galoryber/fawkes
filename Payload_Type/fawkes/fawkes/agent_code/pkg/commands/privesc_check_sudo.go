//go:build linux

package commands

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// privescCheckSudo enumerates sudo rules for the current user
func privescCheckSudo() structs.CommandResult {
	var sb strings.Builder

	// Try sudo -l (may require password — handle gracefully)
	out, err := execCmdTimeout("sudo", "-n", "-l")
	output := strings.TrimSpace(string(out))
	if err != nil {
		if strings.Contains(output, "password is required") || strings.Contains(output, "a password is required") {
			sb.WriteString("sudo -l requires a password (non-interactive mode failed)\n")
			sb.WriteString("This means the user has sudo rules but needs authentication.\n")
		} else if strings.Contains(output, "not allowed") || strings.Contains(output, "not in the sudoers") {
			sb.WriteString("User is NOT in sudoers file.\n")
		} else {
			sb.WriteString(fmt.Sprintf("sudo -l failed: %v\n%s\n", err, output))
		}
	} else {
		sb.WriteString(output)
		sb.WriteString("\n")

		// Flag NOPASSWD entries
		if strings.Contains(output, "NOPASSWD") {
			sb.WriteString("\n[!] NOPASSWD rules detected — potential passwordless privilege escalation")
		}
		// Flag ALL entries
		if strings.Contains(output, "(ALL : ALL) ALL") || strings.Contains(output, "(ALL) ALL") {
			sb.WriteString("\n[!] User has full sudo access (ALL)")
		}
	}

	// Check if /etc/sudoers is readable
	if data, err := os.ReadFile("/etc/sudoers"); err == nil {
		defer structs.ZeroBytes(data) // opsec: clear sudoers rules from memory
		sb.WriteString("\n\n/etc/sudoers is READABLE (unusual — potential misconfiguration):\n")
		// Show non-comment, non-empty lines
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		lineCount := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				sb.WriteString("  " + line + "\n")
				lineCount++
			}
		}
		if lineCount == 0 {
			sb.WriteString("  (no active rules)")
		}
	}

	// Check sudoers.d
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		var readableFiles []string
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join("/etc/sudoers.d", entry.Name())
			if data, err := os.ReadFile(path); err == nil {
				readableFiles = append(readableFiles, fmt.Sprintf("  %s:\n    %s",
					path, strings.ReplaceAll(strings.TrimSpace(string(data)), "\n", "\n    ")))
				structs.ZeroBytes(data) // opsec: clear sudoers.d file contents
			}
		}
		if len(readableFiles) > 0 {
			sb.WriteString(fmt.Sprintf("\n\nReadable /etc/sudoers.d files (%d):\n", len(readableFiles)))
			sb.WriteString(strings.Join(readableFiles, "\n"))
		}
	}

	return successResult(sb.String())
}

// privescCheckSudoToken checks for sudo credential caching that could be reused via ptrace.
// If another process from the same user recently ran sudo, the timestamp file may allow
// sudo without a password (within timeout, typically 15 minutes).
func privescCheckSudoToken() structs.CommandResult {
	var sb strings.Builder

	// Check /var/run/sudo/ts/<username> or /var/db/sudo/ts/<username>
	tsLocations := []string{"/var/run/sudo/ts", "/var/db/sudo/ts", "/run/sudo/ts"}

	username := ""
	if u, err := os.UserHomeDir(); err == nil {
		_ = u
	}
	if cu, err := os.Hostname(); err == nil {
		_ = cu
	}
	// Get actual username
	if uStr := os.Getenv("USER"); uStr != "" {
		username = uStr
	}

	found := false
	for _, tsDir := range tsLocations {
		if _, err := os.Stat(tsDir); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("Sudo timestamp directory exists: %s\n", tsDir))

		if username != "" {
			tsFile := filepath.Join(tsDir, username)
			if info, err := os.Stat(tsFile); err == nil {
				sb.WriteString(fmt.Sprintf("[!] Sudo timestamp file found: %s\n", tsFile))
				sb.WriteString(fmt.Sprintf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05")))
				sb.WriteString("  [!] If within sudo timeout (default 15min), sudo may work without password\n")
				sb.WriteString("  [!] Also exploitable via ptrace on processes from the same tty/session\n")
				found = true
			}
		}

		// List all timestamp files
		entries, err := os.ReadDir(tsDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  Timestamp: %s (modified: %s)\n",
				entry.Name(), info.ModTime().Format("2006-01-02 15:04:05")))
		}
		found = true
	}

	// Check if ptrace is restricted
	if data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		scope := strings.TrimSpace(string(data))
		structs.ZeroBytes(data)
		sb.WriteString(fmt.Sprintf("\nptrace_scope: %s", scope))
		switch scope {
		case "0":
			sb.WriteString(" (classic — any process can ptrace, sudo token reuse possible)")
		case "1":
			sb.WriteString(" (restricted — only parent can ptrace, limits sudo token attack)")
		case "2":
			sb.WriteString(" (admin only — ptrace requires CAP_SYS_PTRACE)")
		case "3":
			sb.WriteString(" (disabled — ptrace completely blocked)")
		}
		sb.WriteString("\n")
	}

	if !found {
		sb.WriteString("No sudo timestamp files found — sudo token reuse not available")
	}

	return successResult(sb.String())
}

// privescCheckPolkit enumerates Polkit rules and policies that may allow
// unprivileged users to perform privileged operations without authentication.
func privescCheckPolkit() structs.CommandResult {
	var sb strings.Builder

	// Check if pkexec has SUID (common privesc vector — CVE-2021-4034)
	if info, err := os.Stat("/usr/bin/pkexec"); err == nil {
		if info.Mode()&os.ModeSetuid != 0 {
			sb.WriteString("[!] /usr/bin/pkexec is SUID — potential CVE-2021-4034 (PwnKit) if unpatched\n")
		}
	}

	// Check Polkit version via polkitd
	if data, err := os.ReadFile("/usr/lib/polkit-1/polkitd"); err == nil {
		structs.ZeroBytes(data)
		sb.WriteString("polkitd binary exists at /usr/lib/polkit-1/polkitd\n")
	} else if data, err := os.ReadFile("/usr/libexec/polkitd"); err == nil {
		structs.ZeroBytes(data)
		sb.WriteString("polkitd binary exists at /usr/libexec/polkitd\n")
	}

	// Scan JavaScript rules in /etc/polkit-1/rules.d/ and /usr/share/polkit-1/rules.d/
	rulesDirs := []string{
		"/etc/polkit-1/rules.d",
		"/usr/share/polkit-1/rules.d",
	}
	var jsRules []string
	for _, dir := range rulesDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := string(data)
			structs.ZeroBytes(data)

			// Flag rules that return YES (allow without password)
			interesting := strings.Contains(content, "return polkit.Result.YES") ||
				strings.Contains(content, "YES")
			writable := isWritableFile(path)

			status := ""
			if interesting {
				status = " [!] ALLOWS WITHOUT AUTH"
			}
			if writable {
				status += " [!] WRITABLE"
			}
			jsRules = append(jsRules, fmt.Sprintf("  %s%s", path, status))
		}
	}

	if len(jsRules) > 0 {
		sb.WriteString(fmt.Sprintf("\nPolkit JS rules (%d):\n", len(jsRules)))
		sb.WriteString(strings.Join(jsRules, "\n"))
		sb.WriteString("\n")
	}

	// Scan legacy .pkla files in /etc/polkit-1/localauthority/
	pklaDir := "/etc/polkit-1/localauthority"
	var pklaFiles []string
	_ = filepath.WalkDir(pklaDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".pkla") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			pklaFiles = append(pklaFiles, fmt.Sprintf("  %s (unreadable)", path))
			return nil
		}
		content := string(data)
		structs.ZeroBytes(data)

		interesting := strings.Contains(content, "ResultAny=yes") ||
			strings.Contains(content, "ResultInactive=yes") ||
			strings.Contains(content, "ResultActive=yes")
		writable := isWritableFile(path)

		status := ""
		if interesting {
			status = " [!] GRANTS ACCESS"
		}
		if writable {
			status += " [!] WRITABLE"
		}
		pklaFiles = append(pklaFiles, fmt.Sprintf("  %s%s", path, status))
		return nil
	})

	if len(pklaFiles) > 0 {
		sb.WriteString(fmt.Sprintf("\nPolkit legacy .pkla files (%d):\n", len(pklaFiles)))
		sb.WriteString(strings.Join(pklaFiles, "\n"))
		sb.WriteString("\n")
	}

	// Scan Polkit action definitions for interesting actions
	actionsDir := "/usr/share/polkit-1/actions"
	var interestingActions []string
	if entries, err := os.ReadDir(actionsDir); err == nil {
		// Only check for writable action files (not parsing XML — too noisy)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".policy") {
				continue
			}
			path := filepath.Join(actionsDir, entry.Name())
			if isWritableFile(path) {
				interestingActions = append(interestingActions,
					fmt.Sprintf("  [!] WRITABLE policy: %s", path))
			}
		}
	}

	if len(interestingActions) > 0 {
		sb.WriteString(fmt.Sprintf("\nWritable Polkit action policies (%d):\n", len(interestingActions)))
		sb.WriteString(strings.Join(interestingActions, "\n"))
		sb.WriteString("\n")
	}

	// Check if rules directories are writable (drop a rule → instant privesc)
	for _, dir := range rulesDirs {
		if isDirWritable(dir) {
			sb.WriteString(fmt.Sprintf("\n[!!] CRITICAL: %s is WRITABLE — drop a .rules file for instant root\n", dir))
		}
	}

	if len(jsRules) == 0 && len(pklaFiles) == 0 && len(interestingActions) == 0 {
		sb.WriteString("\nNo custom Polkit rules or writable policies found")
	}

	return successResult(sb.String())
}
