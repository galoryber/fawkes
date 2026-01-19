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
	// Get current token info before reverting
	var currentToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &currentToken)
	
	var currentInfo string
	if err == nil {
		defer currentToken.Close()
		
		currentUser, err := currentToken.GetTokenUser()
		if err == nil {
			currentUsername, currentDomain, _, err := currentUser.User.Sid.LookupAccount("")
			if err != nil {
				currentUsername = "unknown"
				currentDomain = "unknown"
			}
			currentInfo = fmt.Sprintf("[*] Current impersonated token: %s\\%s\n", currentDomain, currentUsername)
		}
	} else {
		currentInfo = "[*] No active impersonation detected\n"
	}

	// Call RevertToSelf to drop impersonation
	ret, _, err := procRevertToSelf.Call()
	if ret == 0 {
		return structs.CommandResult{
			Output:    currentInfo + fmt.Sprintf("RevertToSelf failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	output := currentInfo + "[+] Successfully reverted to original security context\n"

	// Get new token info (should be process token now)
	processHandle, err := windows.GetCurrentProcess()
	if err == nil {
		var processToken windows.Token
		err = windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY, &processToken)
		if err == nil {
			defer processToken.Close()
			
			processUser, err := processToken.GetTokenUser()
			if err == nil {
				processUsername, processDomain, _, err := processUser.User.Sid.LookupAccount("")
				if err == nil {
					output += fmt.Sprintf("[*] Current token: %s\\%s", processDomain, processUsername)
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
