//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestBuildIptablesArgsBasicAllow(t *testing.T) {
	args := firewallArgs{
		Direction:  "in",
		RuleAction: "allow",
		Protocol:   "tcp",
		Port:       "443",
	}
	cmdArgs, err := buildIptablesArgs(args, "-A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"}
	if len(cmdArgs) != len(expected) {
		t.Fatalf("expected %d args, got %d: %v", len(expected), len(cmdArgs), cmdArgs)
	}
	for i, exp := range expected {
		if cmdArgs[i] != exp {
			t.Errorf("arg[%d] = %q, want %q", i, cmdArgs[i], exp)
		}
	}
}

func TestBuildIptablesArgsBlockOutput(t *testing.T) {
	args := firewallArgs{
		Direction:  "out",
		RuleAction: "block",
		Protocol:   "udp",
		Port:       "53",
		Name:       "block-dns",
	}
	cmdArgs, err := buildIptablesArgs(args, "-D")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmdArgs[0] != "-D" {
		t.Errorf("expected -D operation, got %s", cmdArgs[0])
	}
	if cmdArgs[1] != "OUTPUT" {
		t.Errorf("expected OUTPUT chain for direction 'out', got %s", cmdArgs[1])
	}
	if cmdArgs[len(cmdArgs)-1] != "DROP" {
		t.Errorf("expected DROP target for 'block', got %s", cmdArgs[len(cmdArgs)-1])
	}
	// Check comment is included
	joined := strings.Join(cmdArgs, " ")
	if !strings.Contains(joined, "--comment block-dns") {
		t.Errorf("expected comment in args: %v", cmdArgs)
	}
}

func TestBuildIptablesArgsNoProtocol(t *testing.T) {
	args := firewallArgs{
		Direction:  "in",
		RuleAction: "allow",
	}
	cmdArgs, err := buildIptablesArgs(args, "-A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be: -A INPUT -j ACCEPT (no -p flag)
	if len(cmdArgs) != 4 {
		t.Fatalf("expected 4 args, got %d: %v", len(cmdArgs), cmdArgs)
	}
	for _, arg := range cmdArgs {
		if arg == "-p" {
			t.Error("should not have -p flag when no protocol specified")
		}
	}
}

func TestBuildIptablesArgsPortRequiresProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
	}{
		{"empty protocol", ""},
		{"any protocol", "any"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := firewallArgs{
				Port:     "80",
				Protocol: tt.protocol,
			}
			_, err := buildIptablesArgs(args, "-A")
			if err == nil {
				t.Error("expected error for port without tcp/udp protocol")
			}
			if !strings.Contains(err.Error(), "port requires protocol") {
				t.Errorf("expected 'port requires protocol' error, got: %v", err)
			}
		})
	}
}

func TestBuildIptablesArgsDefaultDirection(t *testing.T) {
	// Default (empty) direction should map to INPUT
	args := firewallArgs{RuleAction: "allow"}
	cmdArgs, err := buildIptablesArgs(args, "-A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmdArgs[1] != "INPUT" {
		t.Errorf("expected INPUT for empty direction, got %s", cmdArgs[1])
	}
}

func TestBuildIptablesArgsDefaultAction(t *testing.T) {
	// Default (empty) rule_action should map to ACCEPT
	args := firewallArgs{}
	cmdArgs, err := buildIptablesArgs(args, "-A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmdArgs[len(cmdArgs)-1] != "ACCEPT" {
		t.Errorf("expected ACCEPT for empty rule_action, got %s", cmdArgs[len(cmdArgs)-1])
	}
}

func TestBuildNftRuleExprBasic(t *testing.T) {
	args := firewallArgs{
		Direction:  "in",
		RuleAction: "allow",
		Protocol:   "tcp",
		Port:       "443",
	}
	chain, ruleExpr, action := buildNftRuleExpr(args)
	if chain != "input" {
		t.Errorf("expected chain 'input', got %q", chain)
	}
	if action != "accept" {
		t.Errorf("expected action 'accept', got %q", action)
	}
	if !strings.Contains(ruleExpr, "tcp") {
		t.Errorf("expected protocol in rule, got %q", ruleExpr)
	}
	if !strings.Contains(ruleExpr, "dport 443") {
		t.Errorf("expected dport in rule, got %q", ruleExpr)
	}
}

func TestBuildNftRuleExprBlockOutput(t *testing.T) {
	args := firewallArgs{
		Direction:  "out",
		RuleAction: "block",
		Name:       "test-rule",
	}
	chain, ruleExpr, action := buildNftRuleExpr(args)
	if chain != "output" {
		t.Errorf("expected chain 'output', got %q", chain)
	}
	if action != "drop" {
		t.Errorf("expected action 'drop', got %q", action)
	}
	if !strings.Contains(ruleExpr, `comment "test-rule"`) {
		t.Errorf("expected comment in rule, got %q", ruleExpr)
	}
}

func TestBuildNftRuleExprMinimal(t *testing.T) {
	args := firewallArgs{}
	chain, ruleExpr, action := buildNftRuleExpr(args)
	if chain != "input" {
		t.Errorf("expected default chain 'input', got %q", chain)
	}
	if action != "accept" {
		t.Errorf("expected default action 'accept', got %q", action)
	}
	// Minimal rule should just be the action
	if ruleExpr != "accept" {
		t.Errorf("expected minimal rule 'accept', got %q", ruleExpr)
	}
}

func TestParseNftHandleFound(t *testing.T) {
	output := `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 443 comment "web-rule" accept # handle 42
		tcp dport 80 comment "http-rule" accept # handle 43
	}
}`
	handle, family := parseNftHandle(output, "web-rule")
	if handle != "42" {
		t.Errorf("expected handle '42', got %q", handle)
	}
	if family != "inet" {
		t.Errorf("expected family 'inet', got %q", family)
	}
}

func TestParseNftHandleIpFamily(t *testing.T) {
	output := `table ip filter {
	chain input {
		tcp dport 22 comment "ssh-rule" accept # handle 7
	}
}`
	handle, family := parseNftHandle(output, "ssh-rule")
	if handle != "7" {
		t.Errorf("expected handle '7', got %q", handle)
	}
	if family != "ip" {
		t.Errorf("expected family 'ip', got %q", family)
	}
}

func TestParseNftHandleNotFound(t *testing.T) {
	output := `table inet filter {
	chain input {
		tcp dport 443 comment "web-rule" accept # handle 42
	}
}`
	handle, family := parseNftHandle(output, "nonexistent-rule")
	if handle != "" || family != "" {
		t.Errorf("expected empty handle/family for missing rule, got handle=%q family=%q", handle, family)
	}
}

func TestParseNftHandleEmptyOutput(t *testing.T) {
	handle, family := parseNftHandle("", "any-rule")
	if handle != "" || family != "" {
		t.Errorf("expected empty for empty output, got handle=%q family=%q", handle, family)
	}
}

func TestParseNftHandleMultipleMatches(t *testing.T) {
	// Should return first match
	output := `table inet filter {
	chain input {
		tcp dport 443 comment "rule-a" accept # handle 10
		tcp dport 80 comment "rule-a" accept # handle 20
	}
}`
	handle, _ := parseNftHandle(output, "rule-a")
	if handle != "10" {
		t.Errorf("expected first match handle '10', got %q", handle)
	}
}
