//go:build windows
// +build windows

package commands

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestSearchSystemTokenViaHandles_NonPrivileged(t *testing.T) {
	// When running as a normal user (non-admin, no SeDebugPrivilege),
	// the function should return an error rather than panic.
	// This validates the error handling path.
	tok, info, err := searchSystemTokenViaHandles()
	if err == nil {
		// If we actually found a SYSTEM token (e.g. running as SYSTEM in CI),
		// that's fine — just verify the token is valid
		if tok == 0 {
			t.Error("got nil error but token is 0")
		}
		if info == "" {
			t.Error("got nil error but info is empty")
		}
		tok.Close()
		return
	}
	// Expected: error because we can't find/access SYSTEM tokens as non-admin
	if tok != 0 {
		t.Errorf("expected zero token on error, got %v", tok)
		windows.Token(tok).Close()
	}
}
