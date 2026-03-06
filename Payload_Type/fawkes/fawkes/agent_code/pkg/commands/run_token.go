//go:build !windows
// +build !windows

package commands

// executeRunCommand runs a command using /bin/sh on non-Windows platforms.
func executeRunCommand(cmdLine string) (string, error) {
	output, err := execCmdTimeout("/bin/sh", "-c", cmdLine)
	return string(output), err
}
