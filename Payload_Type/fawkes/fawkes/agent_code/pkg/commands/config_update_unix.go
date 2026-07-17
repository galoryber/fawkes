//go:build linux || darwin
// +build linux darwin

package commands

import (
	"os"
	"syscall"
)

func launchAndReplace(binaryPath string) error {
	if err := os.Chmod(binaryPath, 0700); err != nil {
		return err
	}

	cmd := safeCmd(binaryPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	_ = cmd.Process.Release()

	go func() {
		os.Exit(0)
	}()

	return nil
}
