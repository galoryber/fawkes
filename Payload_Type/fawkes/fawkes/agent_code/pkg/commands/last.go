package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

type LastCommand struct{}

func (c *LastCommand) Name() string { return "last" }
func (c *LastCommand) Description() string {
	return "Show recent login history and session information"
}

type lastArgs struct {
	Count int    `json:"count"` // Number of entries to show (default: 25)
	User  string `json:"user"`  // Filter by username
}

func (c *LastCommand) Execute(task structs.Task) structs.CommandResult {
	args := lastArgs{Count: 25}
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}
	if args.Count <= 0 {
		args.Count = 25
	}

	output := lastPlatform(args)
	if output == "" {
		output = "No login history available on this platform"
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

// formatLastEntry formats a login entry consistently across platforms
func formatLastEntry(user, tty, host, loginTime, duration string) string {
	if host == "" {
		host = "-"
	}
	if tty == "" {
		tty = "-"
	}
	return fmt.Sprintf("%-16s %-12s %-20s %-22s %s\n", user, tty, host, loginTime, duration)
}

func lastHeader() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-16s %-12s %-20s %-22s %s\n", "USER", "TTY", "FROM", "LOGIN TIME", "DURATION"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")
	return sb.String()
}
