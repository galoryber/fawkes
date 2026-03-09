package commands

import (
	"context"
	"math/rand"
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

// jitterSleep sleeps for a randomized duration between min and max (inclusive).
// Avoids fixed timing signatures that EDR behavioral analysis can detect.
func jitterSleep(min, max time.Duration) {
	if max <= min {
		time.Sleep(min)
		return
	}
	jitter := time.Duration(rand.Int63n(int64(max - min)))
	time.Sleep(min + jitter)
}
