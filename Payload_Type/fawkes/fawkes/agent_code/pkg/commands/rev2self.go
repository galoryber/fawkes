//go:build windows
// +build windows

package commands

import (
	"fmt"

	"fawkes/pkg/structs"
)

type Rev2SelfCommand struct{}

func (c *Rev2SelfCommand) Name() string {
	return "rev2self"
}

func (c *Rev2SelfCommand) Description() string {
	return "Revert to original security context (drop impersonation)"
}

// Execute implements Xenon's TokenRevert from Token.c (lines 268-275)
// and Apollo's Revert from IdentityManager.cs
func (c *Rev2SelfCommand) Execute(task structs.Task) structs.CommandResult {
	// Get current identity before reverting
	var oldIdentity string
	if HasActiveImpersonation() {
		oldIdentity, _ = GetCurrentIdentity()
	}

	// Check if we're actually impersonating
	wasImpersonating := HasActiveImpersonation() || gIdentityToken != 0

	// Revert to original token (Xenon Identity.c lines 35-52)
	if err := RevertCurrentToken(); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("RevertToSelf failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Get new identity after reverting
	newIdentity, err := GetCurrentIdentity()
	if err != nil {
		return structs.CommandResult{
			Output:    "Reverted but failed to get current identity",
			Status:    "success",
			Completed: true,
		}
	}

	// Format output
	var output string
	if wasImpersonating {
		if oldIdentity != "" {
			output = fmt.Sprintf("Was: %s\nReverted to: %s", oldIdentity, newIdentity)
		} else {
			output = fmt.Sprintf("Reverted to: %s", newIdentity)
		}
	} else {
		output = fmt.Sprintf("Not impersonating. Current identity: %s", newIdentity)
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
