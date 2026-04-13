//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

// EventLogCommand provides Unified Logging (log/os_log) access on macOS.
// Uses the `log` CLI tool for querying, streaming, and managing system logs.
type EventLogCommand struct{}

type eventlogArgs struct {
	Action  string `json:"action"`
	Channel string `json:"channel"` // subsystem, process name, or file path
	Filter  string `json:"filter"`  // time window (24h, 7d) or keyword grep
	EventID int    `json:"event_id"`
	Count   int    `json:"count"`
}

func (c *EventLogCommand) Name() string { return "eventlog" }

func (c *EventLogCommand) Description() string {
	return "Manage system logs — list, query, clear, info on macOS (Unified Logging)"
}

func (c *EventLogCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[eventlogArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "list":
		return eventlogDarwinList(args.Filter)
	case "query":
		return eventlogDarwinQuery(args.Channel, args.Filter, args.EventID, args.Count)
	case "clear":
		return eventlogDarwinClear(args.Channel)
	case "info":
		return eventlogDarwinInfo(args.Channel)
	case "enable", "disable":
		return eventlogDarwinToggle(args.Action, args.Channel)
	default:
		return errorf("Unknown action: %s (use list, query, clear, info, enable, disable)", args.Action)
	}
}

// hasLogCommand checks if the macOS `log` utility is available.
func hasLogCommand() bool {
	_, err := exec.LookPath("log")
	return err == nil
}

// eventlogDarwinList lists available log subsystems and /var/log files.
func eventlogDarwinList(filter string) structs.CommandResult {
	var sb strings.Builder

	if hasLogCommand() {
		// List known subsystems by reading the log store predicates
		sb.WriteString("macOS Unified Logging Subsystems\n")
		sb.WriteString(strings.Repeat("=", 50) + "\n\n")

		// Query recent log entries to discover active subsystems
		args := []string{"show", "--last", "1h", "--style", "ndjson", "--info"}
		out, err := execCmdTimeout("log", args...)
		if err == nil {
			subsystems := extractSubsystems(string(out))
			if filter != "" {
				lowerFilter := strings.ToLower(filter)
				var filtered []string
				for _, s := range subsystems {
					if strings.Contains(strings.ToLower(s), lowerFilter) {
						filtered = append(filtered, s)
					}
				}
				subsystems = filtered
			}
			sb.WriteString(fmt.Sprintf("Active subsystems (last 1h): %d\n", len(subsystems)))
			for _, s := range subsystems {
				sb.WriteString(fmt.Sprintf("  %s\n", s))
			}
		} else {
			sb.WriteString("  (could not enumerate subsystems — log show failed)\n")
		}

		// Show log store sizes
		sb.WriteString("\nLog Store:\n")
		for _, dir := range []string{
			"/var/db/diagnostics",
			"/var/db/uuidtext",
		} {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				size := dirSize(dir)
				sb.WriteString(fmt.Sprintf("  %s (%s)\n", dir, formatBytes(uint64(size))))
			}
		}
	} else {
		sb.WriteString("macOS log command not available\n\n")
	}

	// Always list /var/log files as supplementary info
	sb.WriteString("\nLog Files in /var/log/:\n")
	count := eventlogListVarLog(&sb, filter)
	if count == 0 {
		sb.WriteString("  (no matching log files found)\n")
	}

	return successResult(sb.String())
}

// extractSubsystems parses ndjson log output and extracts unique subsystem names.
func extractSubsystems(ndjson string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, line := range strings.Split(ndjson, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Extract subsystem from ndjson: look for "subsystem":"value"
		idx := strings.Index(line, `"subsystem"`)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(`"subsystem"`):]
		// Skip to the value
		colonIdx := strings.Index(rest, ":")
		if colonIdx < 0 {
			continue
		}
		rest = strings.TrimSpace(rest[colonIdx+1:])
		if len(rest) == 0 || rest[0] != '"' {
			continue
		}
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			continue
		}
		subsystem := rest[1 : end+1]
		if subsystem != "" && !seen[subsystem] {
			seen[subsystem] = true
			result = append(result, subsystem)
		}
	}
	return result
}

// eventlogDarwinQuery queries Unified Log entries or log file content.
func eventlogDarwinQuery(channel, filter string, priority, maxCount int) structs.CommandResult {
	if maxCount <= 0 {
		maxCount = 50
	}

	// If channel looks like a file path, read the file directly (no subprocess)
	if strings.HasPrefix(channel, "/") {
		return eventlogQueryFile(channel, filter, maxCount)
	}

	if !hasLogCommand() {
		if channel == "" {
			return errorResult("log command not available. Specify a log file path as channel (e.g., /var/log/system.log)")
		}
		// Try as file path under /var/log
		path := "/var/log/" + channel
		if _, err := os.Stat(path); err == nil {
			return eventlogQueryFile(path, filter, maxCount)
		}
		return errorf("log command not available and /var/log/%s not found", channel)
	}

	// Build log show arguments
	args := []string{"show", "--style", "compact"}

	// Time window from filter
	timeWindow := "1h" // default
	grepPattern := ""
	if filter != "" {
		if _, ok := parseTimeWindow(filter); ok {
			timeWindow = filter
		} else {
			grepPattern = filter
		}
	}
	args = append(args, "--last", timeWindow)

	// Build predicate for channel (subsystem or process)
	var predicates []string
	if channel != "" {
		// Check if it looks like a subsystem (contains dots: com.apple.xxx)
		if strings.Contains(channel, ".") {
			predicates = append(predicates, fmt.Sprintf(`subsystem == "%s"`, channel))
		} else {
			// Treat as process name
			predicates = append(predicates, fmt.Sprintf(`process == "%s"`, channel))
		}
	}

	// Include info-level messages (default is only default+error)
	args = append(args, "--info")

	if len(predicates) > 0 {
		args = append(args, "--predicate", strings.Join(predicates, " AND "))
	}

	out, err := execCmdTimeout("log", args...)
	if err != nil {
		if len(out) > 0 {
			return successResult(string(out))
		}
		return errorf("log show failed: %v", err)
	}

	result := strings.TrimSpace(string(out))

	// Apply grep filter if specified
	if grepPattern != "" {
		lowerPattern := strings.ToLower(grepPattern)
		var filtered []string
		for _, line := range strings.Split(result, "\n") {
			if strings.Contains(strings.ToLower(line), lowerPattern) {
				filtered = append(filtered, line)
			}
		}
		result = strings.Join(filtered, "\n")
	}

	// Limit to maxCount lines (take last N)
	lines := strings.Split(result, "\n")
	if len(lines) > maxCount {
		lines = lines[len(lines)-maxCount:]
	}
	result = strings.Join(lines, "\n")

	if result == "" || result == "Filtering the log data using " {
		var sb strings.Builder
		sb.WriteString("No log entries found")
		if channel != "" {
			sb.WriteString(fmt.Sprintf(" for '%s'", channel))
		}
		if filter != "" {
			sb.WriteString(fmt.Sprintf(" matching '%s'", filter))
		}
		return successResult(sb.String())
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Unified Log entries (max %d, last %s):\n", maxCount, timeWindow))
	if channel != "" {
		sb.WriteString(fmt.Sprintf("Source: %s\n", channel))
	}
	if grepPattern != "" {
		sb.WriteString(fmt.Sprintf("Filter: %s\n", grepPattern))
	}
	sb.WriteString("\n")
	sb.WriteString(result)

	return successResult(sb.String())
}

// eventlogDarwinClear provides guidance on clearing macOS logs.
func eventlogDarwinClear(channel string) structs.CommandResult {
	// If channel is a file path, truncate it directly
	if strings.HasPrefix(channel, "/") {
		if err := os.Truncate(channel, 0); err != nil {
			return errorf("Error truncating %s: %v", channel, err)
		}
		return successf("Truncated %s to 0 bytes", channel)
	}

	// macOS Unified Logging doesn't support selective clearing via CLI.
	// The log store is managed by logd and can only be cleared with root.
	var sb strings.Builder
	sb.WriteString("macOS Unified Logging clear options:\n\n")
	sb.WriteString("  1. Delete log store (requires root):\n")
	sb.WriteString("     sudo rm -rf /var/db/diagnostics/Persist/*\n")
	sb.WriteString("     sudo rm -rf /var/db/diagnostics/Special/*\n")
	sb.WriteString("     sudo rm -rf /var/db/diagnostics/HighVolume/*\n")
	sb.WriteString("     sudo rm -rf /var/db/uuidtext/*\n\n")
	sb.WriteString("  2. Truncate traditional log files:\n")
	sb.WriteString("     eventlog -action clear -channel /var/log/system.log\n")
	sb.WriteString("     eventlog -action clear -channel /var/log/install.log\n\n")
	sb.WriteString("  3. Erase all logs (requires root):\n")
	sb.WriteString("     log erase --all\n\n")
	sb.WriteString("  Note: SIP (System Integrity Protection) may prevent some operations.\n")

	return successResult(sb.String())
}

// eventlogDarwinInfo shows metadata about macOS Unified Logging.
func eventlogDarwinInfo(channel string) structs.CommandResult {
	// If channel is a file path, show file info
	if strings.HasPrefix(channel, "/") {
		return eventlogFileInfo(channel)
	}

	var sb strings.Builder

	if hasLogCommand() {
		sb.WriteString("macOS Unified Logging Information\n")
		sb.WriteString(strings.Repeat("=", 50) + "\n\n")

		// Log stats
		out, err := execCmdTimeout("log", "stats")
		if err == nil {
			output := strings.TrimSpace(string(out))
			// Show first ~40 lines of stats (truncate verbose output)
			lines := strings.Split(output, "\n")
			limit := 40
			if len(lines) < limit {
				limit = len(lines)
			}
			for _, line := range lines[:limit] {
				sb.WriteString(fmt.Sprintf("  %s\n", line))
			}
			if len(lines) > limit {
				sb.WriteString(fmt.Sprintf("  ... (%d more lines)\n", len(lines)-limit))
			}
		} else {
			sb.WriteString("  (log stats not available)\n")
		}

		// Log store sizes
		sb.WriteString("\nLog Store Sizes:\n")
		logDirs := []struct {
			path string
			desc string
		}{
			{"/var/db/diagnostics/Persist", "Persistent logs"},
			{"/var/db/diagnostics/Special", "Special logs"},
			{"/var/db/diagnostics/HighVolume", "High-volume logs"},
			{"/var/db/diagnostics/Signpost", "Signpost logs"},
			{"/var/db/uuidtext", "UUID text cache"},
		}
		for _, d := range logDirs {
			if info, err := os.Stat(d.path); err == nil && info.IsDir() {
				size := dirSize(d.path)
				sb.WriteString(fmt.Sprintf("  %-45s %s\n", d.desc+" ("+d.path+")", formatBytes(uint64(size))))
			}
		}

		// If a specific subsystem/process was requested
		if channel != "" {
			sb.WriteString(fmt.Sprintf("\nRecent entries for '%s':\n", channel))
			var predicate string
			if strings.Contains(channel, ".") {
				predicate = fmt.Sprintf(`subsystem == "%s"`, channel)
			} else {
				predicate = fmt.Sprintf(`process == "%s"`, channel)
			}
			out, err = execCmdTimeout("log", "show", "--last", "1h", "--style", "compact", "--predicate", predicate, "--info")
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				// Skip header line
				dataLines := 0
				for _, line := range lines {
					if !strings.HasPrefix(line, "Filtering") && !strings.HasPrefix(line, "Timestamp") && strings.TrimSpace(line) != "" {
						dataLines++
					}
				}
				sb.WriteString(fmt.Sprintf("  Entries (last 1h): %d\n", dataLines))
			}
		}
	} else {
		sb.WriteString("macOS log command not available\n")
	}

	// Show /var/log summary
	sb.WriteString("\n/var/log Summary:\n")
	sb.WriteString(strings.Repeat("=", 40) + "\n")
	totalSize := dirSize("/var/log")
	sb.WriteString(fmt.Sprintf("  Total size: %s\n", formatBytes(uint64(totalSize))))

	return successResult(sb.String())
}

// eventlogDarwinToggle provides guidance on configuring macOS logging levels.
func eventlogDarwinToggle(action, channel string) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("macOS Unified Logging %s options:\n\n", action))

	if action == "enable" {
		sb.WriteString("  Enable debug/info logging for a subsystem:\n")
		sb.WriteString("    sudo log config --mode 'level:debug' --subsystem <subsystem>\n")
		sb.WriteString("    sudo log config --mode 'level:info' --subsystem <subsystem>\n\n")
		if channel != "" {
			sb.WriteString(fmt.Sprintf("  For '%s':\n", channel))
			sb.WriteString(fmt.Sprintf("    sudo log config --mode 'level:debug' --subsystem %s\n\n", channel))
		}
		sb.WriteString("  Enable persistent logging:\n")
		sb.WriteString("    sudo log config --mode 'persist:default' --subsystem <subsystem>\n\n")
	} else {
		sb.WriteString("  Reset logging to default level:\n")
		sb.WriteString("    sudo log config --mode 'level:default' --subsystem <subsystem>\n\n")
		if channel != "" {
			sb.WriteString(fmt.Sprintf("  For '%s':\n", channel))
			sb.WriteString(fmt.Sprintf("    sudo log config --mode 'level:default' --subsystem %s\n\n", channel))
		}
		sb.WriteString("  Disable persistent logging:\n")
		sb.WriteString("    sudo log config --mode 'persist:off' --subsystem <subsystem>\n\n")
	}

	sb.WriteString("  Common subsystems:\n")
	sb.WriteString("    com.apple.xpc                  — XPC interprocess communication\n")
	sb.WriteString("    com.apple.authd                — Authorization framework\n")
	sb.WriteString("    com.apple.securityd             — Security daemon\n")
	sb.WriteString("    com.apple.opendirectoryd        — Directory services\n")
	sb.WriteString("    com.apple.network               — Network subsystem\n")
	sb.WriteString("    com.apple.launchd               — Process launch\n\n")
	sb.WriteString("  Note: Requires root. SIP may restrict some subsystems.\n")

	return successResult(sb.String())
}
