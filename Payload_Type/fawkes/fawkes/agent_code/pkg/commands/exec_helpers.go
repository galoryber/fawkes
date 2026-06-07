package commands

import (
	"context"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultExecTimeout = 30 * time.Second

// sanitizedEnv returns os.Environ() with entries containing NUL bytes removed.
// Go 1.19+ rejects exec.Command when any env var contains \x00 (CVE-2022-41716).
func sanitizedEnv() []string {
	env := os.Environ()
	clean := env[:0]
	for _, e := range env {
		if !strings.Contains(e, "\x00") {
			clean = append(clean, e)
		}
	}
	return clean
}

// newCmdCtx creates an exec.Cmd with sanitized environment and timeout context.
func newCmdCtx(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = sanitizedEnv()
	return cmd
}

// execCmdTimeout runs a command with a timeout and returns combined output.
func execCmdTimeout(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	defer cancel()
	return newCmdCtx(ctx, name, args...).CombinedOutput()
}

// execCmdTimeoutOutput runs a command with a timeout and returns stdout only.
func execCmdTimeoutOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	defer cancel()
	return newCmdCtx(ctx, name, args...).Output()
}

// execCmdCtx creates an exec.Cmd with the default timeout context.
// Use this when you need to set Stdin or other fields before running.
func execCmdCtx(name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	return newCmdCtx(ctx, name, args...), cancel
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
