//go:build !windows

package commands

import (
	"os"
	"testing"
)

func TestDetectShell_Default(t *testing.T) {
	shell := detectShell()
	if shell == "" {
		t.Error("detectShell() returned empty string")
	}
	// Should be an absolute path
	if shell[0] != '/' {
		t.Errorf("detectShell() returned non-absolute path: %s", shell)
	}
	// File should exist
	if _, err := os.Stat(shell); os.IsNotExist(err) {
		t.Errorf("detectShell() returned non-existent path: %s", shell)
	}
}

func TestDetectShell_FromEnv(t *testing.T) {
	orig := os.Getenv("SHELL")
	defer func() {
		if orig != "" {
			os.Setenv("SHELL", orig)
		} else {
			os.Unsetenv("SHELL")
		}
	}()

	// Set SHELL to a known path
	os.Setenv("SHELL", "/bin/sh")
	shell := detectShell()
	if shell != "/bin/sh" {
		t.Errorf("expected /bin/sh from env, got %s", shell)
	}
}

func TestDetectShell_InvalidEnv(t *testing.T) {
	orig := os.Getenv("SHELL")
	defer func() {
		if orig != "" {
			os.Setenv("SHELL", orig)
		} else {
			os.Unsetenv("SHELL")
		}
	}()

	// Set SHELL to nonexistent path — should fall back to known shells
	os.Setenv("SHELL", "/nonexistent/shell/binary")
	shell := detectShell()
	if shell == "/nonexistent/shell/binary" {
		t.Error("should not use nonexistent SHELL")
	}
	if shell == "" {
		t.Error("should find a fallback shell")
	}
	// Should be a real file
	if _, err := os.Stat(shell); os.IsNotExist(err) {
		t.Errorf("fallback shell does not exist: %s", shell)
	}
}

func TestDetectShell_NoEnv(t *testing.T) {
	orig := os.Getenv("SHELL")
	os.Unsetenv("SHELL")
	defer func() {
		if orig != "" {
			os.Setenv("SHELL", orig)
		}
	}()

	shell := detectShell()
	if shell == "" {
		t.Error("expected fallback shell, got empty")
	}
	// Should return one of the known fallback shells
	known := map[string]bool{"/bin/bash": true, "/bin/zsh": true, "/bin/sh": true}
	if !known[shell] {
		t.Logf("got unexpected shell: %s (still valid if it exists)", shell)
	}
}

func TestPtyCommand_Name(t *testing.T) {
	cmd := &PtyCommand{}
	if cmd.Name() != "pty" {
		t.Errorf("expected 'pty', got %q", cmd.Name())
	}
}

func TestPtyCommand_Description(t *testing.T) {
	cmd := &PtyCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}
