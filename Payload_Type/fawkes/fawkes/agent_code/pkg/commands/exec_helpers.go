package commands

import (
	"context"
	"os/exec"
	"time"
)

const defaultExecTimeout = 30 * time.Second

// execCmdTimeout runs a command with a timeout and returns combined output.
func execCmdTimeout(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// execCmdTimeoutOutput runs a command with a timeout and returns stdout only.
func execCmdTimeoutOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// execCmdCtx creates an exec.Cmd with the default timeout context.
// Use this when you need to set Stdin or other fields before running.
func execCmdCtx(name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	return exec.CommandContext(ctx, name, args...), cancel
}
