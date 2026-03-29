//go:build windows
// +build windows

package commands

import (
	"testing"

	"fawkes/pkg/structs"
)

func TestRev2Self_Name(t *testing.T) {
	cmd := &Rev2SelfCommand{}
	if got := cmd.Name(); got != "rev2self" {
		t.Errorf("Name() = %q, want %q", got, "rev2self")
	}
}

func TestRev2Self_Description(t *testing.T) {
	cmd := &Rev2SelfCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestRev2Self_ExecuteNoImpersonation(t *testing.T) {
	// When not impersonating, rev2self should succeed with a message
	// indicating no impersonation was active
	cmd := &Rev2SelfCommand{}

	// Ensure no active impersonation
	tokenMutex.Lock()
	origToken := gIdentityToken
	gIdentityToken = 0
	tokenMutex.Unlock()

	defer func() {
		tokenMutex.Lock()
		gIdentityToken = origToken
		tokenMutex.Unlock()
	}()

	result := cmd.Execute(structs.Task{Params: ""})
	// rev2self should succeed even when not impersonating
	if result.Status != "success" {
		t.Errorf("rev2self with no impersonation should succeed, got status=%q output=%q", result.Status, result.Output)
	}
}
