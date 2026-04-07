//go:build windows
// +build windows

package commands

import (
	"os/exec"
	"time"

	"fawkes/pkg/structs"
)

// vssShutdownWindows initiates an immediate system shutdown on Windows.
// T1529 — System Shutdown/Reboot
func vssShutdownWindows(args vssArgs) structs.CommandResult {
	if !args.Confirm {
		return errorResult("SAFETY: shutdown requires -confirm true. This will immediately power off the system (T1529 - System Shutdown/Reboot). This is a destructive action used in ransomware/wiper emulation.")
	}

	// shutdown.exe /s = shutdown, /t 0 = no delay, /f = force close apps
	cmd := exec.Command("shutdown.exe", "/s", "/t", "0", "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Shutdown failed: %v\nOutput: %s", err, string(out))
	}

	time.Sleep(1 * time.Second)
	return successResult("Shutdown initiated. System powering off.")
}

// vssRebootWindows initiates an immediate system reboot on Windows.
// T1529 — System Shutdown/Reboot
func vssRebootWindows(args vssArgs) structs.CommandResult {
	if !args.Confirm {
		return errorResult("SAFETY: reboot requires -confirm true. This will immediately reboot the system (T1529 - System Shutdown/Reboot). This is a destructive action used in ransomware/wiper emulation.")
	}

	// shutdown.exe /r = reboot, /t 0 = no delay, /f = force close apps
	cmd := exec.Command("shutdown.exe", "/r", "/t", "0", "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Reboot failed: %v\nOutput: %s", err, string(out))
	}

	time.Sleep(1 * time.Second)
	return successResult("Reboot initiated. System restarting.")
}
