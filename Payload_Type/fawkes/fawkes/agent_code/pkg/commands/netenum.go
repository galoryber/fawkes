//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

type NetEnumCommand struct{}

func (c *NetEnumCommand) Name() string {
	return "net-enum"
}

func (c *NetEnumCommand) Description() string {
	return "Enumerate users, groups, and domain information via net.exe"
}

type netEnumArgs struct {
	Action string `json:"action"`
	Target string `json:"target"`
}

func (c *NetEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args netEnumArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (action). Use: users, localgroups, domainusers, domaingroups, groupmembers, domaininfo",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "users":
		return netEnumLocalUsers()
	case "localgroups":
		return netEnumLocalGroups()
	case "groupmembers":
		return netEnumGroupMembers(args.Target)
	case "domainusers":
		return netEnumDomainUsers()
	case "domaingroups":
		return netEnumDomainGroups()
	case "domaininfo":
		return netEnumDomainInfo()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: users, localgroups, groupmembers, domainusers, domaingroups, domaininfo", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func netEnumLocalUsers() structs.CommandResult {
	output, err := runNet([]string{"user"})
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating local users: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Local Users:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

func netEnumLocalGroups() structs.CommandResult {
	output, err := runNet([]string{"localgroup"})
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating local groups: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Local Groups:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

func netEnumGroupMembers(group string) structs.CommandResult {
	if group == "" {
		return structs.CommandResult{
			Output:    "Error: target (group name) is required for groupmembers action",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := runNet([]string{"localgroup", group})
	if err != nil && output == "" {
		// Try domain group if local fails
		domainOutput, domainErr := runNet([]string{"group", group, "/domain"})
		if domainErr != nil && domainOutput == "" {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Local group error: %v\nDomain group error: %v", err, domainErr),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Domain Group '%s' Members:\n%s", group, domainOutput),
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Group '%s' Members:\n%s", group, output),
		Status:    "success",
		Completed: true,
	}
}

func netEnumDomainUsers() structs.CommandResult {
	output, err := runNet([]string{"user", "/domain"})
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating domain users: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Domain Users:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

func netEnumDomainGroups() structs.CommandResult {
	output, err := runNet([]string{"group", "/domain"})
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating domain groups: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Domain Groups:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

func netEnumDomainInfo() structs.CommandResult {
	// Gather multiple pieces of domain info
	var sb strings.Builder

	// Get domain accounts/config overview
	output, err := runNet([]string{"accounts", "/domain"})
	if err != nil {
		sb.WriteString(fmt.Sprintf("Domain accounts info: (error: %v)\n%s\n\n", err, output))
	} else {
		sb.WriteString(fmt.Sprintf("Domain Account Policy:\n%s\n\n", output))
	}

	// Get domain controller info via nltest
	dcOutput, dcErr := exec.Command("nltest.exe", "/dclist:").CombinedOutput()
	if dcErr == nil {
		sb.WriteString(fmt.Sprintf("Domain Controllers:\n%s\n\n", strings.TrimSpace(string(dcOutput))))
	}

	// Get trusted domains
	trustOutput, trustErr := exec.Command("nltest.exe", "/domain_trusts").CombinedOutput()
	if trustErr == nil {
		sb.WriteString(fmt.Sprintf("Domain Trusts:\n%s\n", strings.TrimSpace(string(trustOutput))))
	}

	result := sb.String()
	if result == "" {
		return structs.CommandResult{
			Output:    "Error: unable to retrieve domain information (machine may not be domain-joined)",
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    result,
		Status:    "success",
		Completed: true,
	}
}

func runNet(args []string) (string, error) {
	cmd := exec.Command("net.exe", args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
