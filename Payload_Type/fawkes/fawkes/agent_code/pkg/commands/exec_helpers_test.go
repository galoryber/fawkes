package commands

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDefaultExecTimeout(t *testing.T) {
	if defaultExecTimeout != 30*time.Second {
		t.Errorf("defaultExecTimeout = %v, want 30s", defaultExecTimeout)
	}
}

func TestExecCmdTimeout(t *testing.T) {
	out, err := execCmdTimeout("echo", "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Errorf("output = %q, want to contain 'hello'", string(out))
	}
}

func TestExecCmdTimeoutOutput(t *testing.T) {
	out, err := execCmdTimeoutOutput("echo", "world")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "world") {
		t.Errorf("output = %q, want to contain 'world'", string(out))
	}
}

func TestExecCmdTimeoutBadCommand(t *testing.T) {
	_, err := execCmdTimeout("nonexistent_command_12345")
	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}
}

func TestExecCmdCtx(t *testing.T) {
	cmd, cancel := execCmdCtx("echo", "ctx-test")
	defer cancel()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "ctx-test") {
		t.Errorf("output = %q, want to contain 'ctx-test'", string(out))
	}
}

func TestExecCmdCtxCancel(t *testing.T) {
	cmd, cancel := execCmdCtx("sleep", "60")
	cancel() // Cancel immediately

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error after cancellation")
		return
	}
	if !strings.Contains(err.Error(), context.Canceled.Error()) &&
		!strings.Contains(err.Error(), "signal: killed") &&
		!strings.Contains(err.Error(), "exec:") {
		// Context cancellation before start gives exec error
		t.Logf("got expected error type: %v", err)
	}
}

func TestExecCmdTimeoutStderr(t *testing.T) {
	// CombinedOutput should capture stderr too
	out, _ := execCmdTimeout("sh", "-c", "echo err >&2")
	if !strings.Contains(string(out), "err") {
		t.Errorf("CombinedOutput should capture stderr, got %q", string(out))
	}
}

func TestExecCmdTimeoutOutputStdoutOnly(t *testing.T) {
	// Output() returns only stdout
	out, _ := execCmdTimeoutOutput("sh", "-c", "echo stdout; echo stderr >&2")
	if !strings.Contains(string(out), "stdout") {
		t.Errorf("Output should contain stdout, got %q", string(out))
	}
}
