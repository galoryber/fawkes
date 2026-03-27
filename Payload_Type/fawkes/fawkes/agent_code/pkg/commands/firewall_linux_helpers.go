//go:build linux

package commands

import (
	"fmt"
	"strings"
)

// buildIptablesArgs builds iptables command arguments for add (-A) or delete (-D) operations.
// Returns the argument list or an error if validation fails.
func buildIptablesArgs(args firewallArgs, operation string) ([]string, error) {
	chain := "INPUT"
	if strings.EqualFold(args.Direction, "out") {
		chain = "OUTPUT"
	}

	target := "ACCEPT"
	if strings.EqualFold(args.RuleAction, "block") {
		target = "DROP"
	}

	cmdArgs := []string{operation, chain}

	proto := strings.ToLower(args.Protocol)
	if proto != "" && proto != "any" {
		cmdArgs = append(cmdArgs, "-p", proto)
	}

	if args.Port != "" {
		if proto == "" || proto == "any" {
			return nil, fmt.Errorf("port requires protocol to be 'tcp' or 'udp'")
		}
		cmdArgs = append(cmdArgs, "--dport", args.Port)
	}

	if args.Name != "" {
		cmdArgs = append(cmdArgs, "-m", "comment", "--comment", args.Name)
	}

	cmdArgs = append(cmdArgs, "-j", target)
	return cmdArgs, nil
}

// buildNftRuleExpr builds an nftables rule expression and returns chain, expression, and action.
func buildNftRuleExpr(args firewallArgs) (chain, ruleExpr, action string) {
	chain = "input"
	if strings.EqualFold(args.Direction, "out") {
		chain = "output"
	}

	action = "accept"
	if strings.EqualFold(args.RuleAction, "block") {
		action = "drop"
	}

	var ruleParts []string
	proto := strings.ToLower(args.Protocol)
	if proto != "" && proto != "any" {
		ruleParts = append(ruleParts, proto)
		if args.Port != "" {
			ruleParts = append(ruleParts, "dport", args.Port)
		}
	}

	if args.Name != "" {
		ruleParts = append(ruleParts, "comment", fmt.Sprintf(`"%s"`, args.Name))
	}
	ruleParts = append(ruleParts, action)
	ruleExpr = strings.Join(ruleParts, " ")
	return
}

// parseNftHandle extracts the handle number and family from nft -a output
// for a rule matching the given comment name.
func parseNftHandle(output string, name string) (handle, family string) {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, name) && strings.Contains(line, "# handle") {
			idx := strings.LastIndex(line, "# handle ")
			if idx >= 0 {
				handle = strings.TrimSpace(line[idx+len("# handle "):])
				if strings.Contains(output, "inet") {
					family = "inet"
				} else {
					family = "ip"
				}
				return
			}
		}
	}
	return "", ""
}
