//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"

	"fawkes/pkg/structs"
)

type GetPrivsCommand struct{}

func (c *GetPrivsCommand) Name() string {
	return "getprivs"
}

func (c *GetPrivsCommand) Description() string {
	return "List process entitlements and security context"
}

func (c *GetPrivsCommand) Execute(task structs.Task) structs.CommandResult {
	var params getPrivsParams
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
			params.Action = "list"
		}
	}
	if params.Action == "" {
		params.Action = "list"
	}

	switch params.Action {
	case "list":
		return listDarwinPrivileges()
	case "enable", "disable", "strip":
		return structs.CommandResult{
			Output:    fmt.Sprintf("Action '%s' is not supported on macOS (use Windows for token privilege manipulation)", params.Action),
			Status:    "error",
			Completed: true,
		}
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'list')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func listDarwinPrivileges() structs.CommandResult {
	identity := fmt.Sprintf("uid=%d euid=%d gid=%d egid=%d",
		os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid())

	u, err := user.Current()
	if err == nil {
		identity = fmt.Sprintf("%s (%s)", u.Username, identity)
	}

	source := "process"
	if os.Geteuid() == 0 {
		source = "root"
	}

	var entries []privOutputEntry

	// Check root status
	if os.Geteuid() == 0 {
		entries = append(entries, privOutputEntry{
			Name:        "root",
			Status:      "Enabled",
			Description: "Running as root — full system access",
		})
	}

	// Group memberships (admin group = elevated)
	if groups, err := getGroupMemberships(); err == nil {
		for _, g := range groups {
			status := "Member"
			desc := "Group membership"
			if g == "admin" || g == "wheel" {
				status = "Enabled"
				desc = "Administrative group — sudo access"
			}
			entries = append(entries, privOutputEntry{
				Name:        "group:" + g,
				Status:      status,
				Description: desc,
			})
		}
	}

	// Sandbox status
	sandboxed := checkSandboxStatus()
	if sandboxed {
		entries = append(entries, privOutputEntry{
			Name:        "sandbox",
			Status:      "Enabled",
			Description: "Process is sandboxed — restricted resource access",
		})
	} else {
		entries = append(entries, privOutputEntry{
			Name:        "sandbox",
			Status:      "Disabled",
			Description: "Process is not sandboxed — unrestricted",
		})
	}

	// Code signing entitlements
	if entitlements := getEntitlements(); len(entitlements) > 0 {
		for _, ent := range entitlements {
			entries = append(entries, privOutputEntry{
				Name:        ent,
				Status:      "Granted",
				Description: "Code signing entitlement",
			})
		}
	}

	integrity := "Standard"
	if os.Geteuid() == 0 {
		integrity = "Root"
	}
	if sandboxed {
		integrity += " | Sandboxed"
	}

	output := privsOutput{
		Identity:   identity,
		Source:     source,
		Integrity:  integrity,
		Privileges: entries,
	}

	data, err := json.Marshal(output)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling results: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

// getGroupMemberships returns the group names for the current user
func getGroupMemberships() ([]string, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, gid := range gids {
		if g, err := user.LookupGroupId(gid); err == nil {
			names = append(names, g.Name)
		}
	}
	return names, nil
}

// checkSandboxStatus checks if the current process is sandboxed
func checkSandboxStatus() bool {
	out, err := execCmdTimeout("sandbox-check", "--pid", fmt.Sprintf("%d", os.Getpid()))
	if err != nil {
		// sandbox-check exits 1 if not sandboxed, 0 if sandboxed
		return false
	}
	return !strings.Contains(string(out), "not sandboxed")
}

// getEntitlements retrieves code signing entitlements for the current process
func getEntitlements() []string {
	exePath, err := os.Executable()
	if err != nil {
		return nil
	}
	out, err := execCmdTimeout("codesign", "-d", "--entitlements", "-", "--xml", exePath)
	if err != nil {
		return nil
	}
	// Parse entitlement keys from the XML plist output
	return parseEntitlementKeys(string(out))
}

// parseEntitlementKeys extracts entitlement key names from codesign XML output
func parseEntitlementKeys(xmlData string) []string {
	var keys []string
	lines := strings.Split(xmlData, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "<key>" || strings.HasPrefix(trimmed, "<key>") {
			// Extract key name between <key> and </key>
			key := strings.TrimPrefix(trimmed, "<key>")
			key = strings.TrimSuffix(key, "</key>")
			key = strings.TrimSpace(key)
			if key != "" {
				// Check if next line has <true/> to confirm it's granted
				granted := true
				if i+1 < len(lines) {
					nextLine := strings.TrimSpace(lines[i+1])
					if nextLine == "<false/>" {
						granted = false
					}
				}
				if granted {
					keys = append(keys, key)
				}
			}
		}
	}
	return keys
}
