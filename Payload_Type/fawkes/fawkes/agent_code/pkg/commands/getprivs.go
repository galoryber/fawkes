//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

type GetPrivsCommand struct{}

func (c *GetPrivsCommand) Name() string {
	return "getprivs"
}

func (c *GetPrivsCommand) Description() string {
	return "List privileges of the current token (thread or process)"
}

func (c *GetPrivsCommand) Execute(task structs.Task) structs.CommandResult {
	// Reuses getCurrentToken from whoami_windows.go
	token, tokenSource, err := getCurrentToken()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get current token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer token.Close()

	// Get token identity
	identity, _ := GetTokenUserInfo(token)

	// Reuses getTokenPrivileges from whoami_windows.go
	privs, err := getTokenPrivileges(token)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enumerate privileges: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Reuses getTokenIntegrityLevel from whoami_windows.go
	integrity, err := getTokenIntegrityLevel(token)
	if err != nil {
		integrity = "Unknown"
	}

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Token: %s (%s)\n", identity, tokenSource))
	sb.WriteString(fmt.Sprintf("Integrity: %s\n", integrity))
	sb.WriteString(fmt.Sprintf("Privileges: %d\n\n", len(privs)))

	// Count enabled
	enabledCount := 0
	for _, p := range privs {
		if p.status == "Enabled" || p.status == "Enabled (Default)" {
			enabledCount++
		}
	}
	sb.WriteString(fmt.Sprintf("Enabled: %d / %d\n\n", enabledCount, len(privs)))

	// Header
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
