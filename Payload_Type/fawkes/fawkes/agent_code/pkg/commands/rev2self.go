//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"

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
	var debugLog strings.Builder
	var output string

	// Get current context before reverting
	debugLog.WriteString("[DEBUG] Checking for thread token before revert...\n")
	var beforeUsername, beforeDomain string
	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &threadToken)
	if err == nil {
		// We have a thread token (impersonating)
		debugLog.WriteString("[DEBUG] Thread token found (currently impersonating)\n")
		defer threadToken.Close()
		threadUser, err := threadToken.GetTokenUser()
		if err == nil {
			beforeUsername, beforeDomain, _, err = threadUser.User.Sid.LookupAccount("")
			if err == nil {
				output += fmt.Sprintf("Current impersonated identity: %s\\%s\n", beforeDomain, beforeUsername)
				debugLog.WriteString(fmt.Sprintf("[DEBUG] Impersonated as: %s\\%s\n", beforeDomain, beforeUsername))
			}
		}
	} else {
		debugLog.WriteString(fmt.Sprintf("[DEBUG] No thread token found (not currently impersonating): %v\n", err))
		output += "Note: Not currently impersonating\n"
	}

	// Call RevertToSelf to drop impersonation (like Sliver)
	debugLog.WriteString("[DEBUG] Calling RevertToSelf...\n")
	ret, _, err := procRevertToSelf.Call()
	if ret == 0 {
		return structs.CommandResult{
			Output:    debugLog.String() + "\n" + output + fmt.Sprintf("RevertToSelf failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	debugLog.WriteString("[DEBUG] RevertToSelf succeeded\n")

	// Get context after reverting (should be process token now)
	debugLog.WriteString("[DEBUG] Verifying revert by checking process token...\n")
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
					output += fmt.Sprintf("Reverted to %s\\%s", afterDomain, afterUsername)
					debugLog.WriteString(fmt.Sprintf("[DEBUG] Confirmed revert to: %s\\%s\n", afterDomain, afterUsername))
				}
			}
		}
	}

	return structs.CommandResult{
		Output:    debugLog.String() + "\n" + strings.TrimSpace(output),
		Status:    "success",
		Completed: true,
	}
}
