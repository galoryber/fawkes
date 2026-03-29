//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestRunWithToken_Constants(t *testing.T) {
	// Verify creation flag constants used by run_token
	if CREATE_NO_WINDOW != 0x08000000 {
		t.Errorf("CREATE_NO_WINDOW = 0x%X, want 0x08000000", CREATE_NO_WINDOW)
	}
	if EXTENDED_STARTUPINFO_PRESENT != 0x00080000 {
		t.Errorf("EXTENDED_STARTUPINFO_PRESENT = 0x%X, want 0x00080000", EXTENDED_STARTUPINFO_PRESENT)
	}
}

func TestExecuteRunCommand_EmptyCommand(t *testing.T) {
	// An empty command should still execute (cmd.exe /c "") — it's not an error at parse level
	// but may produce empty output. This tests that the function doesn't panic.
	tokenMutex.Lock()
	origToken := gIdentityToken
	gIdentityToken = 0
	tokenMutex.Unlock()

	defer func() {
		tokenMutex.Lock()
		gIdentityToken = origToken
		tokenMutex.Unlock()
	}()

	output, err := executeRunCommand("")
	// Empty command may or may not error depending on cmd.exe behavior,
	// but it should not panic
	_ = output
	_ = err
}

func TestExecuteRunCommand_SimpleCommand(t *testing.T) {
	// Test a simple command without impersonation
	tokenMutex.Lock()
	origToken := gIdentityToken
	gIdentityToken = 0
	tokenMutex.Unlock()

	defer func() {
		tokenMutex.Lock()
		gIdentityToken = origToken
		tokenMutex.Unlock()
	}()

	output, err := executeRunCommand("echo hello")
	if err != nil {
		t.Fatalf("echo command should succeed: %v", err)
	}
	if len(output) == 0 {
		t.Error("Expected output from echo command")
	}
}

func TestStartupInfoEx_Size(t *testing.T) {
	// Verify STARTUPINFOEX contains the expected fields
	var siex STARTUPINFOEX
	siex.StartupInfo.Cb = 1
	if siex.StartupInfo.Cb != 1 {
		t.Error("Failed to set STARTUPINFO.Cb field")
	}
	siex.AttributeList = nil
	if siex.AttributeList != nil {
		t.Error("AttributeList should be nil")
	}
}
