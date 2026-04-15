//go:build linux

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// persistEnumCron checks system and user crontabs.
func persistEnumCron(sb *strings.Builder) int {
	sb.WriteString("--- Cron Jobs ---\n")
	count := 0

	// System crontab
	if content, err := os.ReadFile("/etc/crontab"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [/etc/crontab] %s\n", line))
			count++
		}
	}

	// /etc/cron.d/ directory
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join("/etc/cron.d", entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				sb.WriteString(fmt.Sprintf("  [%s] %s\n", path, line))
				count++
			}
		}
	}

	// User crontabs in /var/spool/cron/crontabs/
	cronDirs := []string{"/var/spool/cron/crontabs", "/var/spool/cron"}
	for _, cronDir := range cronDirs {
		entries, err := os.ReadDir(cronDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(cronDir, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				sb.WriteString(fmt.Sprintf("  [%s:%s] %s\n", entry.Name(), cronDir, line))
				count++
			}
		}
	}

	// Periodic cron directories
	periodicDirs := []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range periodicDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", dir, entry.Name()))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumSystemd checks for non-default systemd services and timers.
func persistEnumSystemd(sb *strings.Builder) int {
	sb.WriteString("--- Systemd Units ---\n")
	count := 0

	// User and system unit directories
	homeDir := currentHomeDir()
	unitDirs := []struct {
		path string
		desc string
	}{
		{"/etc/systemd/system", "system"},
		{filepath.Join(homeDir, ".config/systemd/user"), "user"},
	}

	for _, ud := range unitDirs {
		entries, err := os.ReadDir(ud.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			// Skip default targets, wants directories, and symlinks to /dev/null (masked)
			if entry.IsDir() || name == "default.target" {
				continue
			}
			// Only show .service and .timer files
			if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [%s] %s\n", ud.desc, name))
				count++
				continue
			}

			// Check if it's a symlink (enabled unit)
			detail := ""
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(filepath.Join(ud.path, name))
				if err == nil {
					detail = fmt.Sprintf(" → %s", target)
				}
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s%s\n", ud.desc, name, detail))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumDBus checks for custom D-Bus service files that could activate backdoor processes (T1543).
func persistEnumDBus(sb *strings.Builder) int {
	sb.WriteString("--- D-Bus Services ---\n")
	count := 0

	homeDir := currentHomeDir()

	// D-Bus service directories — system-wide and user session
	dbusDirs := []struct {
		path string
		desc string
	}{
		{"/usr/share/dbus-1/system-services", "system"},
		{"/usr/share/dbus-1/services", "session"},
		{"/usr/local/share/dbus-1/services", "local session"},
		{"/usr/local/share/dbus-1/system-services", "local system"},
		{filepath.Join(homeDir, ".local/share/dbus-1/services"), "user session"},
	}

	for _, dd := range dbusDirs {
		entries, err := os.ReadDir(dd.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
				continue
			}
			path := filepath.Join(dd.path, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [%s] %s (unreadable)\n", dd.desc, entry.Name()))
				count++
				continue
			}

			// Extract Exec= line to show what runs on activation
			execLine := ""
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Exec=") {
					execLine = line[5:]
					break
				}
			}

			if execLine != "" {
				sb.WriteString(fmt.Sprintf("  [%s] %s → %s\n", dd.desc, entry.Name(), execLine))
			} else {
				sb.WriteString(fmt.Sprintf("  [%s] %s\n", dd.desc, entry.Name()))
			}
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumAtJobs checks for scheduled at jobs (one-time execution).
func persistEnumAtJobs(sb *strings.Builder) int {
	sb.WriteString("--- At Jobs ---\n")
	count := 0

	atDirs := []string{"/var/spool/at", "/var/spool/atjobs"}

	for _, dir := range atDirs {
		entries, err := os.ReadDir(dir)
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
			sb.WriteString(fmt.Sprintf("  [%s] %s (%d bytes, modified: %s)\n",
				dir, entry.Name(), info.Size(), info.ModTime().Format("2006-01-02 15:04")))
			count++
		}
	}

	// Check /etc/at.allow and /etc/at.deny for access control
	if _, err := os.Stat("/etc/at.allow"); err == nil {
		sb.WriteString("  [access] /etc/at.allow exists (only listed users can use at)\n")
	} else if _, err := os.Stat("/etc/at.deny"); err == nil {
		sb.WriteString("  [access] /etc/at.deny exists (listed users denied at)\n")
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumAnacron checks anacron configuration for periodic job persistence (T1053).
func persistEnumAnacron(sb *strings.Builder) int {
	sb.WriteString("--- Anacron ---\n")
	count := 0

	// Main anacrontab
	if content, err := os.ReadFile("/etc/anacrontab"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Skip variable assignments
			if strings.Contains(line, "=") && !strings.Contains(line, " ") {
				continue
			}
			// Anacron format: period delay job-identifier command
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				sb.WriteString(fmt.Sprintf("  [anacrontab] period=%s delay=%s id=%s cmd=%s\n",
					fields[0], fields[1], fields[2], strings.Join(fields[3:], " ")))
				count++
			}
		}
	}

	// Anacron spool — tracks last execution times
	if entries, err := os.ReadDir("/var/spool/anacron"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			content, err := os.ReadFile(filepath.Join("/var/spool/anacron", entry.Name()))
			if err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [spool] %s last ran: %s\n",
				entry.Name(), strings.TrimSpace(string(content))))
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}
