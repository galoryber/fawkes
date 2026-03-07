//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

type FirewallCommand struct{}

func (c *FirewallCommand) Name() string        { return "firewall" }
func (c *FirewallCommand) Description() string { return "Query macOS firewall status (pf/ALF)" }

func (c *FirewallCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: list, status",
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
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: list, status", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func darwinFirewallStatus() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== macOS Firewall Status ===\n\n")

	// Check Application Layer Firewall (ALF) via socketfilterfw
	alfOut, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").CombinedOutput()
	if err == nil {
		sb.WriteString("Application Firewall (ALF):\n")
		sb.WriteString("  " + strings.TrimSpace(string(alfOut)) + "\n")
	}

	// Check stealth mode
	stealthOut, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode").CombinedOutput()
	if err == nil {
		sb.WriteString("  " + strings.TrimSpace(string(stealthOut)) + "\n")
	}

	// Check block-all mode
	blockOut, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall").CombinedOutput()
	if err == nil {
		sb.WriteString("  " + strings.TrimSpace(string(blockOut)) + "\n")
	}

	sb.WriteString("\n")

	// Check PF (packet filter) status
	pfOut, err := exec.Command("pfctl", "-s", "info").CombinedOutput()
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

func darwinFirewallList() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== macOS Firewall Rules ===\n\n")

	// List ALF application rules
	alfOut, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps").CombinedOutput()
	if err == nil {
		sb.WriteString("--- Application Firewall Rules ---\n")
		sb.WriteString(strings.TrimSpace(string(alfOut)))
		sb.WriteString("\n\n")
	}

	// List PF rules
	pfOut, err := exec.Command("pfctl", "-s", "rules").CombinedOutput()
	if err == nil {
		output := strings.TrimSpace(string(pfOut))
		if output != "" {
			sb.WriteString("--- Packet Filter Rules ---\n")
			sb.WriteString(output)
			sb.WriteString("\n\n")
		}
	}

	// List PF NAT rules
	natOut, err := exec.Command("pfctl", "-s", "nat").CombinedOutput()
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
