//go:build !windows
// +build !windows

package commands

import "os/exec"

// configureProcessToken is a no-op on non-Windows platforms.
func configureProcessToken(cmd *exec.Cmd) {}

// executeRunCommand runs a command using /bin/sh on non-Windows platforms.
func executeRunCommand(cmdLine string) (string, error) {
	output, err := exec.Command("/bin/sh", "-c", cmdLine).CombinedOutput()
	return string(output), err
}
