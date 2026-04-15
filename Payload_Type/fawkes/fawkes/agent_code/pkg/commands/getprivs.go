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
			return errorResult("Error: 'privilege' parameter required for enable action")
		}
		return adjustPrivilege(params.Privilege, true)
	case "disable":
		if params.Privilege == "" {
			return errorResult("Error: 'privilege' parameter required for disable action")
		}
		return adjustPrivilege(params.Privilege, false)
	case "strip":
		return stripPrivileges()
	default:
		return errorf("Unknown action: %s (use 'list', 'enable', 'disable', or 'strip')", params.Action)
	}
}

func listPrivileges() structs.CommandResult {
	token, tokenSource, err := getCurrentToken()
	if err != nil {
		return errorf("Failed to get current token: %v", err)
	}
	defer token.Close()

	identity, _ := GetTokenUserInfo(token)
	privs, err := getTokenPrivileges(token)
	if err != nil {
		return errorf("Failed to enumerate privileges: %v", err)
	}

	integrity, err := getTokenIntegrityLevel(token)
	if err != nil {
		integrity = "Unknown"
	}

	var entries []privOutputEntry
	for _, p := range privs {
		entries = append(entries, privOutputEntry{
			Name:        p.name,
			Status:      p.status,
			Description: privilegeDescription(p.name),
		})
	}

	output := privsOutput{
		Identity:   identity,
		Source:     tokenSource,
		Integrity:  integrity,
		Privileges: entries,
	}

	data, err := json.Marshal(output)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return successResult(string(data))
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
		return 0, fmt.Errorf("GetCurrentProcess: %w", err)
	}

	var processToken windows.Token
	err = windows.OpenProcessToken(processHandle,
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &processToken)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	return processToken, nil
}

func adjustPrivilege(privName string, enable bool) structs.CommandResult {
	token, err := getTokenForAdjust()
	if err != nil {
		return errorf("Failed to get token: %v", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privName), &luid)
	if err != nil {
		return errorf("Privilege '%s' not found: %v", privName, err)
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
		return errorf("AdjustTokenPrivileges failed: %v", err)
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

	return successResult(output)
}

func stripPrivileges() structs.CommandResult {
	token, err := getTokenForAdjust()
	if err != nil {
		return errorf("Failed to get token: %v", err)
	}
	defer token.Close()

	// Get current privileges
	privs, err := getTokenPrivileges(token)
	if err != nil {
		return errorf("Failed to enumerate privileges: %v", err)
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

	return successResult(sb.String())
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
