//go:build !windows
// +build !windows

package commands

import "os/exec"

// configureProcessToken is a no-op on non-Windows platforms.
func configureProcessToken(cmd *exec.Cmd) {}
