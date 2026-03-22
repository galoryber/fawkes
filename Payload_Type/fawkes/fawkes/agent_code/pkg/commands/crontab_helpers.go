//go:build !windows

package commands

import (
	"fmt"
	"strings"
)

// buildCrontabEntry constructs a crontab line from the given arguments.
// Returns the entry string and an error if neither entry nor program is specified.
func buildCrontabEntry(args crontabArgs) (string, error) {
	if args.Entry != "" {
		return args.Entry, nil
	}
	if args.Program == "" {
		return "", fmt.Errorf("provide either 'entry' (raw cron line) or 'program' (with optional schedule/args)")
	}
	schedule := args.Schedule
	if schedule == "" {
		schedule = "@reboot"
	}
	if args.Args != "" {
		return fmt.Sprintf("%s %s %s", schedule, args.Program, args.Args), nil
	}
	return fmt.Sprintf("%s %s", schedule, args.Program), nil
}

// mergeCrontab appends a new entry to an existing crontab string.
func mergeCrontab(existing, newEntry string) string {
	crontab := strings.TrimRight(existing, "\n")
	if crontab != "" {
		crontab += "\n"
	}
	crontab += newEntry + "\n"
	return crontab
}

// filterCrontabLines removes lines containing matchStr and returns the remaining
// lines plus a count of removed entries.
func filterCrontabLines(lines []string, matchStr string) ([]string, int) {
	var kept []string
	removedCount := 0
	for _, line := range lines {
		if strings.Contains(line, matchStr) {
			removedCount++
			continue
		}
		kept = append(kept, line)
	}
	return kept, removedCount
}
