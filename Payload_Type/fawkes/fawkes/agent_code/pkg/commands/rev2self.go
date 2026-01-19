//go:build windows
// +build windows

package commands

import (
	"fmt"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type Rev2SelfCommand struct{}

func (c *Rev2SelfCommand) Name() string {
	return "rev2self"
}

func (c *Rev2SelfCommand) Description() string {
	return "Revert to original security context (drop impersonation)"
}

func (c *Rev2SelfCommand) Execute(task structs.Task) structs.CommandResult {
	var output string

	// Get current context before reverting
	var beforeUsername, beforeDomain string
	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &threadToken)
	if err == nil {
		// We have a thread token (impersonating)
		defer threadToken.Close()
		threadUser, err := threadToken.GetTokenUser()
		if err == nil {
			beforeUsername, beforeDomain, _, err = threadUser.User.Sid.LookupAccount("")
			if err == nil {
				output += fmt.Sprintf("Current impersonated identity: %s\\%s\n", beforeDomain, beforeUsername)
			}
		}
	}

	// Call RevertToSelf to drop impersonation
	ret, _, err := procRevertToSelf.Call()
	if ret == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("RevertToSelf failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Get context after reverting (should be process token now)
	processHandle, err := windows.GetCurrentProcess()
	if err == nil {
		var processToken windows.Token
		err = windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY, &processToken)
		if err == nil {
			defer processToken.Close()
			processUser, err := processToken.GetTokenUser()
			if err == nil {
				afterUsername, afterDomain, _, err := processUser.User.Sid.LookupAccount("")
				if err == nil {
					output += fmt.Sprintf("Reverted identity to %s\\%s", afterDomain, afterUsername)
				}
			}
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
