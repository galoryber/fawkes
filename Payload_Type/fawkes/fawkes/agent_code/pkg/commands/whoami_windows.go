//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// advapi32 proc for privilege lookup (advapi32 DLL loaded in tokenutils.go)
var procLookupPrivilegeNameW = advapi32.NewProc("LookupPrivilegeNameW")

type WhoamiCommand struct{}

func (c *WhoamiCommand) Name() string {
	return "whoami"
}

func (c *WhoamiCommand) Description() string {
	return "Display current user identity and security context"
}

func (c *WhoamiCommand) Execute(task structs.Task) structs.CommandResult {
	var lines []string

	// Determine token source: thread (impersonation) or process
	impersonating := HasActiveImpersonation()
	token, tokenSource, err := getCurrentToken()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get current token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer token.Close()

	// Username
	identity, err := GetTokenUserInfo(token)
	if err != nil {
		identity = "(unknown)"
	}
	lines = append(lines, fmt.Sprintf("User:        %s", identity))

	// SID
	sid, err := getTokenSID(token)
	if err == nil {
		lines = append(lines, fmt.Sprintf("SID:         %s", sid))
	}

	// Token type
	lines = append(lines, fmt.Sprintf("Token:       %s", tokenSource))
	if impersonating {
		lines = append(lines, "Impersonating: Yes")
	}

	// Integrity level
	integrity, err := getTokenIntegrityLevel(token)
	if err == nil {
		lines = append(lines, fmt.Sprintf("Integrity:   %s", integrity))
	}

	// Privileges
	privs, err := getTokenPrivileges(token)
	if err == nil && len(privs) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Privileges:")
		for _, p := range privs {
			lines = append(lines, fmt.Sprintf("  %-40s %s", p.name, p.status))
		}
	}

	return structs.CommandResult{
		Output:    strings.Join(lines, "\n"),
		Status:    "success",
		Completed: true,
	}
}

// getCurrentToken returns the active token and its source description.
func getCurrentToken() (windows.Token, string, error) {
	// Try thread token first (impersonation)
	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &threadToken)
	if err == nil {
		return threadToken, "Impersonation (thread)", nil
	}

	// Fall back to process token
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, "", fmt.Errorf("GetCurrentProcess: %v", err)
	}

	var processToken windows.Token
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY, &processToken)
	if err != nil {
		return 0, "", fmt.Errorf("OpenProcessToken: %v", err)
	}

	return processToken, "Primary (process)", nil
}

// getTokenSID returns the string SID for the token's user.
func getTokenSID(token windows.Token) (string, error) {
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return tokenUser.User.Sid.String(), nil
}

// integrityLevel maps well-known RID values to names.
func integrityLevelName(rid uint32) string {
	switch {
	case rid >= 0x4000: // SECURITY_MANDATORY_SYSTEM_RID
		return "System"
	case rid >= 0x3000: // SECURITY_MANDATORY_HIGH_RID
		return "High"
	case rid >= 0x2000: // SECURITY_MANDATORY_MEDIUM_RID
		return "Medium"
	case rid >= 0x1000: // SECURITY_MANDATORY_LOW_RID
		return "Low"
	default:
		return "Untrusted"
	}
}

// getTokenIntegrityLevel returns the integrity level string for a token.
func getTokenIntegrityLevel(token windows.Token) (string, error) {
	// TokenIntegrityLevel = 25
	const tokenIntegrityLevel = 25

	var needed uint32
	// First call to get required buffer size
	windows.GetTokenInformation(token, tokenIntegrityLevel, nil, 0, &needed)
	if needed == 0 {
		return "", fmt.Errorf("GetTokenInformation returned zero size")
	}

	buf := make([]byte, needed)
	err := windows.GetTokenInformation(token, tokenIntegrityLevel, &buf[0], needed, &needed)
	if err != nil {
		return "", fmt.Errorf("GetTokenInformation: %v", err)
	}

	// TOKEN_MANDATORY_LABEL structure: first field is SID_AND_ATTRIBUTES
	// SID_AND_ATTRIBUTES: Sid *SID, Attributes uint32
	type sidAndAttributes struct {
		Sid        *windows.SID
		Attributes uint32
	}
	label := (*sidAndAttributes)(unsafe.Pointer(&buf[0]))

	// The integrity level is the last sub-authority (RID) of the SID
	subAuthorityCount := label.Sid.SubAuthorityCount()
	if subAuthorityCount == 0 {
		return "", fmt.Errorf("integrity SID has no sub-authorities")
	}

	sidStr := label.Sid.String()
	// Parse the last sub-authority value from the SID string
	// SID format: S-1-16-<rid>
	rid := uint32(0)
	fmt.Sscanf(sidStr, "S-1-16-%d", &rid)

	return fmt.Sprintf("%s (S-1-16-%d)", integrityLevelName(rid), rid), nil
}

type privilegeInfo struct {
	name   string
	status string
}

// getTokenPrivileges returns the list of privileges for a token.
func getTokenPrivileges(token windows.Token) ([]privilegeInfo, error) {
	var needed uint32
	// TokenPrivileges = 3
	const tokenPrivileges = 3

	windows.GetTokenInformation(token, tokenPrivileges, nil, 0, &needed)
	if needed == 0 {
		return nil, fmt.Errorf("GetTokenInformation returned zero size")
	}

	buf := make([]byte, needed)
	err := windows.GetTokenInformation(token, tokenPrivileges, &buf[0], needed, &needed)
	if err != nil {
		return nil, fmt.Errorf("GetTokenInformation: %v", err)
	}

	// TOKEN_PRIVILEGES: PrivilegeCount uint32, Privileges []LUID_AND_ATTRIBUTES
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	if count == 0 {
		return nil, nil
	}

	type luidAndAttributes struct {
		Luid       windows.LUID
		Attributes uint32
	}

	// Offset past the count field (4 bytes, but may have padding)
	privOffset := unsafe.Sizeof(uint32(0))
	privs := make([]privilegeInfo, 0, count)

	for i := uint32(0); i < count; i++ {
		la := (*luidAndAttributes)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + privOffset + uintptr(i)*unsafe.Sizeof(luidAndAttributes{})))

		// Look up privilege name via LookupPrivilegeNameW
		var nameLen uint32 = 256
		nameBuf := make([]uint16, nameLen)
		ret, _, err := procLookupPrivilegeNameW.Call(
			0, // lpSystemName (NULL = local)
			uintptr(unsafe.Pointer(&la.Luid)),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
		)
		if ret == 0 {
			_ = err
			continue
		}
		name := windows.UTF16ToString(nameBuf[:nameLen])

		// Determine status
		const (
			SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
			SE_PRIVILEGE_ENABLED            = 0x00000002
			SE_PRIVILEGE_REMOVED            = 0x00000004
		)
		status := "Disabled"
		if la.Attributes&SE_PRIVILEGE_ENABLED != 0 {
			status = "Enabled"
		}
		if la.Attributes&SE_PRIVILEGE_ENABLED_BY_DEFAULT != 0 && la.Attributes&SE_PRIVILEGE_ENABLED != 0 {
			status = "Enabled (Default)"
		}

		privs = append(privs, privilegeInfo{name: name, status: status})
	}

	return privs, nil
}
