//go:build darwin

package commands

import (
	"fmt"
	"strings"
)

// lastFailedPlatform queries macOS unified log for failed authentication attempts.
// Uses `log show` with predicate filter for failed auth events.
func lastFailedPlatform(args lastArgs) []lastLoginEntry {
	// Try /var/log/secure.log first (older macOS), then unified log
	out, err := execCmdTimeout("log", "show", "--predicate",
		`eventMessage CONTAINS "authentication failure" OR eventMessage CONTAINS "Failed password" OR eventMessage CONTAINS "failed to authenticate"`,
		"--style", "syslog", "--last", "7d", "--info")
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		// Fallback: parse /var/log/secure.log
		return lastFailedFromSecureLog(args)
	}

	var entries []lastLoginEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Filtering") || strings.HasPrefix(line, "Timestamp") {
			continue
		}
		if args.User != "" && !strings.Contains(line, args.User) {
			continue
		}
		if len(entries) >= args.Count {
			break
		}

		// Extract timestamp from beginning of syslog-format line
		loginTime := "-"
		if len(line) > 24 {
			loginTime = line[:24]
		}

		entries = append(entries, lastLoginEntry{
			User:      line,
			TTY:       "-",
			From:      "-",
			LoginTime: loginTime,
			Duration:  "FAILED",
		})
	}

	return entries
}

// lastFailedFromSecureLog parses /var/log/secure.log for failed auth lines.
func lastFailedFromSecureLog(args lastArgs) []lastLoginEntry {
	out, err := execCmdTimeout("cat", "/var/log/secure.log")
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var entries []lastLoginEntry
	for i := len(lines) - 1; i >= 0 && len(entries) < args.Count; i-- {
		line := lines[i]
		if !strings.Contains(line, "authentication failure") && !strings.Contains(line, "Failed password") {
			continue
		}
		if args.User != "" && !strings.Contains(line, args.User) {
			continue
		}
		entries = append(entries, lastLoginEntry{
			User:      line,
			TTY:       "-",
			From:      "-",
			LoginTime: "-",
			Duration:  "FAILED",
		})
	}

	return entries
}

func lastPlatform(args lastArgs) []lastLoginEntry {
	cmdArgs := []string{"-n", fmt.Sprintf("%d", args.Count)}
	if args.User != "" {
		cmdArgs = append(cmdArgs, args.User)
	}

	out, err := execCmdTimeout("last", cmdArgs...)
	if err != nil {
		return nil
	}

	var entries []lastLoginEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "wtmp") || strings.HasPrefix(line, "reboot") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		user := fields[0]
		tty := fields[1]
		// Remaining fields are date/time info
		rest := strings.Join(fields[2:], " ")

		entries = append(entries, lastLoginEntry{
			User:      user,
			TTY:       tty,
			LoginTime: rest,
			From:      "-",
		})
	}

	return entries
}

// lastRebootPlatform uses `last reboot` to show system boot events on macOS.
func lastRebootPlatform(args lastArgs) []lastLoginEntry {
	cmdArgs := []string{"reboot"}
	if args.Count > 0 {
		cmdArgs = append(cmdArgs, "-n", fmt.Sprintf("%d", args.Count))
	}

	out, err := execCmdTimeout("last", cmdArgs...)
	if err != nil {
		return nil
	}

	var entries []lastLoginEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "wtmp") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// macOS `last reboot` format: "reboot  ~  Mon Mar 26 14:30"
		rest := strings.Join(fields[2:], " ")

		eventType := "boot"
		if strings.Contains(line, "shutdown") {
			eventType = "shutdown"
		}

		entries = append(entries, lastLoginEntry{
			User:      "system",
			TTY:       eventType,
			From:      "-",
			LoginTime: rest,
		})
	}

	return entries
}
