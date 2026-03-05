//go:build darwin

package commands

import (
	"fmt"
	"strings"
)

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
