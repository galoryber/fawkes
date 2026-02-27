package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// WhoCommand shows currently logged-in users/sessions
type WhoCommand struct{}

func (c *WhoCommand) Name() string        { return "who" }
func (c *WhoCommand) Description() string { return "Show currently logged-in users and active sessions" }

type whoArgs struct {
	All bool `json:"all"` // Show all sessions including system accounts
}

func (c *WhoCommand) Execute(task structs.Task) structs.CommandResult {
	var args whoArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}

	output := whoPlatform(args)
	if output == "" {
		output = "No active user sessions found"
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// whoHeader returns the column header for who output
func whoHeader() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-20s %-14s %-22s %-20s %s\n", "USER", "TTY/SESSION", "LOGIN TIME", "FROM", "STATUS"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")
	return sb.String()
}

// whoEntry formats a single logged-in user entry
func whoEntry(user, tty, loginTime, from, status string) string {
	if from == "" {
		from = "-"
	}
	if tty == "" {
		tty = "-"
	}
	if status == "" {
		status = "active"
	}
	return fmt.Sprintf("%-20s %-14s %-22s %-20s %s\n", user, tty, loginTime, from, status)
}
