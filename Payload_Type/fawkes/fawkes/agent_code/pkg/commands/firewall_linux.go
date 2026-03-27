//go:build linux

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
func (c *FirewallCommand) Description() string { return "Manage Linux firewall (iptables/nftables)" }

func (c *FirewallCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Actions: list, add, delete, status")
	}

	var args firewallArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return linuxFirewallList(args)
	case "status":
		return linuxFirewallStatus()
	case "add":
		return linuxFirewallAdd(args)
	case "delete":
		return linuxFirewallDelete(args)
	case "enable", "disable":
		return errorResult("Linux does not have a global firewall toggle.\nUse 'add' or 'delete' to manage individual rules,\nor manage the firewall service via systemctl (iptables/nftables/ufw).")
	default:
		return errorf("Unknown action: %s\nAvailable: list, add, delete, status", args.Action)
	}
}

// lookPathFunc is a testable wrapper for exec.LookPath.
var lookPathFunc = exec.LookPath

// linuxFirewallBackend detects whether nftables or iptables is available.
// Returns "nft" or "iptables" or "" if neither is found.
func linuxFirewallBackend() string {
	if _, err := lookPathFunc("nft"); err == nil {
		return "nft"
	}
	if _, err := lookPathFunc("iptables"); err == nil {
		return "iptables"
	}
	return ""
}

func linuxFirewallStatus() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Linux Firewall Status ===\n\n")

	backend := linuxFirewallBackend()
	if backend == "" {
		return errorResult("Neither nft nor iptables found in PATH")
	}
	sb.WriteString(fmt.Sprintf("Backend: %s\n\n", backend))

	if backend == "nft" {
		// nftables status
		out, err := execCmdTimeout("nft", "list", "tables")
		if err != nil {
			sb.WriteString(fmt.Sprintf("nft list tables: %v (may require root)\n", err))
		} else {
			tables := strings.TrimSpace(string(out))
			if tables == "" {
				sb.WriteString("No nftables tables configured\n")
			} else {
				sb.WriteString("Tables:\n")
				for _, line := range strings.Split(tables, "\n") {
					sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(line)))
				}
			}
		}

		// Chain and rule counts
		out, err = execCmdTimeout("nft", "list", "ruleset")
		if err == nil {
			ruleset := string(out)
			chains := strings.Count(ruleset, "chain ")
			rules := strings.Count(ruleset, "counter")
			sb.WriteString(fmt.Sprintf("\nChains: %d  |  Rules with counters: %d\n", chains, rules))
		}
	} else {
		// iptables status — show chain policies and rule counts
		for _, table := range []string{"filter", "nat", "mangle"} {
			out, err := execCmdTimeout("iptables", "-t", table, "-L", "-n", "--line-numbers")
			if err != nil {
				continue
			}
			output := strings.TrimSpace(string(out))
			if output == "" {
				continue
			}
			sb.WriteString(fmt.Sprintf("--- %s table ---\n", table))
			// Show just chain headers with policies
			for _, line := range strings.Split(output, "\n") {
				if strings.HasPrefix(line, "Chain ") {
					sb.WriteString(fmt.Sprintf("  %s\n", line))
				}
			}
		}

		// IPv6
		if _, err := lookPathFunc("ip6tables"); err == nil {
			out, err := execCmdTimeout("ip6tables", "-L", "-n", "--line-numbers")
			if err == nil {
				output := strings.TrimSpace(string(out))
				if output != "" {
					sb.WriteString("\n--- IPv6 filter table ---\n")
					for _, line := range strings.Split(output, "\n") {
						if strings.HasPrefix(line, "Chain ") {
							sb.WriteString(fmt.Sprintf("  %s\n", line))
						}
					}
				}
			}
		}
	}

	// Check for ufw
	if _, err := lookPathFunc("ufw"); err == nil {
		out, err := execCmdTimeout("ufw", "status")
		if err == nil {
			sb.WriteString(fmt.Sprintf("\n--- UFW ---\n%s\n", strings.TrimSpace(string(out))))
		}
	}

	return successResult(sb.String())
}

func linuxFirewallList(args firewallArgs) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Linux Firewall Rules ===\n\n")

	backend := linuxFirewallBackend()
	if backend == "" {
		return errorResult("Neither nft nor iptables found in PATH")
	}
	sb.WriteString(fmt.Sprintf("Backend: %s\n\n", backend))

	if backend == "nft" {
		out, err := execCmdTimeout("nft", "list", "ruleset")
		if err != nil {
			return errorf("nft list ruleset failed: %v (may require root)", err)
		}
		output := strings.TrimSpace(string(out))
		if output == "" {
			sb.WriteString("No rules configured\n")
		} else {
			if args.Filter != "" {
				// Filter lines containing the substring
				for _, line := range strings.Split(output, "\n") {
					if strings.Contains(strings.ToLower(line), strings.ToLower(args.Filter)) {
						sb.WriteString(line + "\n")
					}
				}
			} else {
				sb.WriteString(output + "\n")
			}
		}
	} else {
		// iptables — list all tables
		for _, table := range []string{"filter", "nat", "mangle", "raw"} {
			out, err := execCmdTimeout("iptables", "-t", table, "-L", "-n", "-v", "--line-numbers")
			if err != nil {
				continue
			}
			output := strings.TrimSpace(string(out))
			if output == "" {
				continue
			}

			if args.Filter != "" {
				// Filter matching lines (keep chain headers for context)
				sb.WriteString(fmt.Sprintf("--- %s table (filtered: %s) ---\n", table, args.Filter))
				for _, line := range strings.Split(output, "\n") {
					if strings.HasPrefix(line, "Chain ") ||
						strings.Contains(strings.ToLower(line), strings.ToLower(args.Filter)) {
						sb.WriteString(line + "\n")
					}
				}
				sb.WriteString("\n")
			} else {
				sb.WriteString(fmt.Sprintf("--- %s table ---\n%s\n\n", table, output))
			}
		}
	}

	return successResult(sb.String())
}

func linuxFirewallAdd(args firewallArgs) structs.CommandResult {
	backend := linuxFirewallBackend()
	if backend == "" {
		return errorResult("Neither nft nor iptables found in PATH")
	}

	if backend == "nft" {
		return linuxNftAdd(args)
	}
	return linuxIptablesAdd(args)
}

func linuxIptablesAdd(args firewallArgs) structs.CommandResult {
	cmdArgs, err := buildIptablesArgs(args, "-A")
	if err != nil {
		return errorf("Error: %v", err)
	}

	out, execErr := execCmdTimeout("iptables", cmdArgs...)
	if execErr != nil {
		return errorf("iptables add failed: %v\n%s", execErr, string(out))
	}

	chain := cmdArgs[1]
	target := cmdArgs[len(cmdArgs)-1]
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Added iptables rule: %s %s → %s\n", chain, strings.Join(cmdArgs[2:], " "), target))
	if args.Name != "" {
		sb.WriteString(fmt.Sprintf("Comment: %s\n", args.Name))
	}
	return successResult(sb.String())
}

func linuxNftAdd(args firewallArgs) structs.CommandResult {
	chain, ruleExpr, action := buildNftRuleExpr(args)

	nftCmd := fmt.Sprintf("add rule inet filter %s %s", chain, ruleExpr)
	_, err := execCmdTimeout("nft", strings.Fields(nftCmd)...)
	if err != nil {
		// Try with ip (legacy) table if inet fails
		nftCmd = fmt.Sprintf("add rule ip filter %s %s", chain, ruleExpr)
		out, err := execCmdTimeout("nft", strings.Fields(nftCmd)...)
		if err != nil {
			return errorf("nft add rule failed: %v\n%s\nCommand: nft %s", err, string(out), nftCmd)
		}
	}

	return successf("Added nftables rule: %s chain %s → %s", chain, ruleExpr, action)
}

func linuxFirewallDelete(args firewallArgs) structs.CommandResult {
	backend := linuxFirewallBackend()
	if backend == "" {
		return errorResult("Neither nft nor iptables found in PATH")
	}

	if backend == "nft" {
		return linuxNftDelete(args)
	}
	return linuxIptablesDelete(args)
}

func linuxIptablesDelete(args firewallArgs) structs.CommandResult {
	cmdArgs, err := buildIptablesArgs(args, "-D")
	if err != nil {
		return errorf("Error: %v", err)
	}

	out, execErr := execCmdTimeout("iptables", cmdArgs...)
	if execErr != nil {
		return errorf("iptables delete failed: %v\n%s", execErr, string(out))
	}

	chain := cmdArgs[1]
	return successf("Deleted iptables rule: %s %s", chain, strings.Join(cmdArgs[2:], " "))
}

func linuxNftDelete(args firewallArgs) structs.CommandResult {
	// nft delete requires a handle number. If we have a name/comment, search for it.
	if args.Name == "" {
		return errorResult("Error: 'name' (rule comment) is required to identify the rule to delete on nftables")
	}

	chain := "input"
	if strings.EqualFold(args.Direction, "out") {
		chain = "output"
	}

	// List rules with handles to find the matching one
	out, err := execCmdTimeout("nft", "-a", "list", "chain", "inet", "filter", chain)
	if err != nil {
		// Try ip table
		out, err = execCmdTimeout("nft", "-a", "list", "chain", "ip", "filter", chain)
		if err != nil {
			return errorf("nft list chain failed: %v\n%s", err, string(out))
		}
	}

	// Find rule with matching comment
	handle, family := parseNftHandle(string(out), args.Name)

	if handle == "" {
		return errorf("No rule with comment '%s' found in %s chain", args.Name, chain)
	}

	out, err = execCmdTimeout("nft", "delete", "rule", family, "filter", chain, "handle", handle)
	if err != nil {
		return errorf("nft delete rule failed: %v\n%s", err, string(out))
	}

	return successf("Deleted nftables rule (handle %s) from %s chain", handle, chain)
}
