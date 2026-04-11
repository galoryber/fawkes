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
		return errorResult("Error: parameters required. Actions: list, add, delete, enable, disable, status")
	}

	var args firewallArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
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
	case "pf-add":
		return darwinPfAdd(args)
	case "pf-delete":
		return darwinPfDelete(args)
	case "pf-list":
		return darwinPfList(args)
	default:
		return errorf("Unknown action: %s\nAvailable: list, add, delete, enable, disable, status, pf-add, pf-delete, pf-list", args.Action)
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

	return successResult(sb.String())
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
		return errorf("Error setting firewall state: %v\n%s", err, string(out))
	}

	return successf("%s macOS Application Firewall\n%s", label, strings.TrimSpace(string(out)))
}

// darwinFirewallAdd adds an application to the ALF and sets its allow/block policy.
func darwinFirewallAdd(args firewallArgs) structs.CommandResult {
	if args.Program == "" {
		return errorResult("Error: program path is required for add action")
	}

	// Add the application to the firewall
	out, err := execCmdTimeout(socketFilterFW, "--add", args.Program)
	if err != nil {
		return errorf("Error adding application: %v\n%s", err, string(out))
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

	return successResult(sb.String())
}

// darwinFirewallDelete removes an application from the ALF.
func darwinFirewallDelete(args firewallArgs) structs.CommandResult {
	if args.Program == "" {
		return errorResult("Error: program path is required for delete action")
	}

	out, err := execCmdTimeout(socketFilterFW, "--remove", args.Program)
	if err != nil {
		return errorf("Error removing application: %v\n%s", err, string(out))
	}

	return successf("Removed: %s", strings.TrimSpace(string(out)))
}

// buildPfRule constructs a pf rule string from firewall args.
func buildPfRule(args firewallArgs) string {
	action := "pass"
	if strings.EqualFold(args.RuleAction, "block") {
		action = "block"
	}

	direction := "in"
	if strings.EqualFold(args.Direction, "out") {
		direction = "out"
	}

	rule := fmt.Sprintf("%s %s", action, direction)

	proto := strings.ToLower(args.Protocol)
	if proto != "" && proto != "any" {
		rule += fmt.Sprintf(" proto %s", proto)
	}

	rule += " from any to any"
	if args.Port != "" {
		rule += fmt.Sprintf(" port %s", args.Port)
	}

	return rule
}

// darwinPfAdd adds a pf rule to a named anchor.
func darwinPfAdd(args firewallArgs) structs.CommandResult {
	anchor := args.Name
	if anchor == "" {
		anchor = "fawkes"
	}

	rule := buildPfRule(args)

	// Read existing rules in the anchor (may fail if anchor doesn't exist yet)
	existing, _ := execCmdTimeout("pfctl", "-a", anchor, "-s", "rules")
	allRules := strings.TrimSpace(string(existing))
	if allRules != "" {
		allRules += "\n"
	}
	allRules += rule + "\n"

	// Load rules into anchor via stdin
	cmd, cancel := execCmdCtx("pfctl", "-a", anchor, "-f", "/dev/stdin")
	defer cancel()
	cmd.Stdin = strings.NewReader(allRules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("pfctl add rule failed: %v\n%s\nRule: %s", err, string(out), rule)
	}

	return successf("Added pf rule to anchor '%s': %s", anchor, rule)
}

// darwinPfDelete flushes all rules from a named pf anchor (clean removal).
func darwinPfDelete(args firewallArgs) structs.CommandResult {
	anchor := args.Name
	if anchor == "" {
		anchor = "fawkes"
	}

	out, err := execCmdTimeout("pfctl", "-a", anchor, "-F", "rules")
	if err != nil {
		return errorf("pfctl flush anchor failed: %v\n%s", err, string(out))
	}

	return successf("Flushed all rules from pf anchor '%s'\n%s", anchor, strings.TrimSpace(string(out)))
}

// darwinPfList lists rules in a named pf anchor.
func darwinPfList(args firewallArgs) structs.CommandResult {
	anchor := args.Name
	if anchor == "" {
		anchor = "fawkes"
	}

	out, err := execCmdTimeout("pfctl", "-a", anchor, "-s", "rules")
	if err != nil {
		return errorf("pfctl list anchor rules failed: %v\n%s", err, string(out))
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		return successf("No rules in pf anchor '%s'", anchor)
	}

	return successf("PF anchor '%s' rules:\n%s", anchor, output)
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

	return successResult(sb.String())
}
