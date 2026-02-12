//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

type NetSharesCommand struct{}

func (c *NetSharesCommand) Name() string {
	return "net-shares"
}

func (c *NetSharesCommand) Description() string {
	return "Enumerate network shares and mapped drives via net.exe"
}

type netSharesArgs struct {
	Action string `json:"action"`
	Target string `json:"target"`
}

func (c *NetSharesCommand) Execute(task structs.Task) structs.CommandResult {
	var args netSharesArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (action). Use: local, remote, mapped",
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
	case "local":
		return netSharesLocal()
	case "remote":
		return netSharesRemote(args.Target)
	case "mapped":
		return netSharesMapped()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: local, remote, mapped", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func netSharesLocal() structs.CommandResult {
	cmd := exec.Command("net.exe", "share")
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating local shares: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Local Shares:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

func netSharesRemote(target string) structs.CommandResult {
	if target == "" {
		return structs.CommandResult{
			Output:    "Error: target (hostname or IP) is required for remote action",
			Status:    "error",
			Completed: true,
		}
	}

	// Ensure target has UNC prefix
	if !strings.HasPrefix(target, "\\\\") {
		target = "\\\\" + target
	}

	cmd := exec.Command("net.exe", "view", target)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating shares on %s: %v", target, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Shares on %s:\n%s", target, output),
		Status:    "success",
		Completed: true,
	}
}

func netSharesMapped() structs.CommandResult {
	cmd := exec.Command("net.exe", "use")
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating mapped drives: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Mapped Drives:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}
