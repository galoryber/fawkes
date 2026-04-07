//go:build darwin
// +build darwin

package commands

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type VSSCommand struct{}

func (c *VSSCommand) Name() string {
	return "vss"
}

func (c *VSSCommand) Description() string {
	return "Impact techniques — shutdown, reboot (T1529). macOS does not support VSS operations."
}

func (c *VSSCommand) Execute(task structs.Task) structs.CommandResult {
	var args vssArgs
	if task.Params == "" {
		return errorResult("Error: parameters required.\nmacOS actions: shutdown, reboot")
	}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "shutdown":
		return vssShutdown(args)
	case "reboot":
		return vssReboot(args)
	default:
		return errorf("Unknown action: %s\nmacOS actions: shutdown, reboot\n(VSS operations are Windows-only)", args.Action)
	}
}

func vssShutdown(args vssArgs) structs.CommandResult {
	if !args.Confirm {
		return errorResult("SAFETY: shutdown requires -confirm true. This will immediately power off the system (T1529 - System Shutdown/Reboot). This is a destructive action used in ransomware/wiper emulation.")
	}

	cmd := exec.Command("shutdown", "-h", "now")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to halt
		cmd2 := exec.Command("halt")
		out2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return errorf("Shutdown failed: %v\nOutput: %s %s", err2, string(out), string(out2))
		}
	}

	time.Sleep(1 * time.Second)
	return successResult("Shutdown initiated. System powering off.")
}

func vssReboot(args vssArgs) structs.CommandResult {
	if !args.Confirm {
		return errorResult("SAFETY: reboot requires -confirm true. This will immediately reboot the system (T1529 - System Shutdown/Reboot). This is a destructive action used in ransomware/wiper emulation.")
	}

	cmd := exec.Command("shutdown", "-r", "now")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to reboot
		cmd2 := exec.Command("reboot")
		out2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return errorf("Reboot failed: %v\nOutput: %s %s", err2, string(out), string(out2))
		}
	}

	time.Sleep(1 * time.Second)
	return successResult("Reboot initiated. System restarting.")
}
