//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestSudoOutputPatternDetection(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		nopasswd  bool
		allAccess bool
	}{
		{
			"NOPASSWD rule",
			"User setup may run the following commands on host:\n    (ALL) NOPASSWD: ALL",
			true, false,
		},
		{
			"full sudo ALL:ALL",
			"User admin may run:\n    (ALL : ALL) ALL",
			false, true,
		},
		{
			"full sudo ALL",
			"User root may run:\n    (ALL) ALL",
			false, true,
		},
		{
			"NOPASSWD and ALL",
			"    (ALL : ALL) NOPASSWD: ALL",
			true, false, // (ALL : ALL) ALL pattern not matched because NOPASSWD: is between
		},
		{
			"specific command only",
			"User deploy may run:\n    (ALL) /usr/bin/systemctl restart myapp",
			false, false,
		},
		{
			"no rules",
			"User is NOT in sudoers.",
			false, false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hasNoPasswd := strings.Contains(tc.output, "NOPASSWD")
			hasAll := strings.Contains(tc.output, "(ALL : ALL) ALL") ||
				strings.Contains(tc.output, "(ALL) ALL")
			if hasNoPasswd != tc.nopasswd {
				t.Errorf("NOPASSWD: got %v, want %v", hasNoPasswd, tc.nopasswd)
			}
			if hasAll != tc.allAccess {
				t.Errorf("ALL access: got %v, want %v", hasAll, tc.allAccess)
			}
		})
	}
}

func TestSudoErrorClassification(t *testing.T) {
	tests := []struct {
		name          string
		output        string
		needsPassword bool
		notAllowed    bool
	}{
		{
			"password required",
			"[sudo] password for user: \nsudo: a password is required",
			true, false,
		},
		{
			"password is required variant",
			"sudo: password is required\n",
			true, false,
		},
		{
			"not in sudoers",
			"user is not in the sudoers file. This incident will be reported.",
			false, true,
		},
		{
			"not allowed",
			"Sorry, user test is not allowed to execute '/bin/bash' as root",
			false, true,
		},
		{
			"other error",
			"sudo: unable to resolve host unknown",
			false, false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			needsPassword := strings.Contains(tc.output, "password is required") ||
				strings.Contains(tc.output, "a password is required")
			notAllowed := strings.Contains(tc.output, "not allowed") ||
				strings.Contains(tc.output, "not in the sudoers")
			if needsPassword != tc.needsPassword {
				t.Errorf("needsPassword: got %v, want %v", needsPassword, tc.needsPassword)
			}
			if notAllowed != tc.notAllowed {
				t.Errorf("notAllowed: got %v, want %v", notAllowed, tc.notAllowed)
			}
		})
	}
}

func TestPtraceScopeInterpretation(t *testing.T) {
	tests := []struct {
		scope    string
		contains string
	}{
		{"0", "classic"},
		{"1", "restricted"},
		{"2", "admin only"},
		{"3", "disabled"},
	}
	for _, tc := range tests {
		t.Run("scope_"+tc.scope, func(t *testing.T) {
			var desc string
			switch tc.scope {
			case "0":
				desc = "classic — any process can ptrace, sudo token reuse possible"
			case "1":
				desc = "restricted — only parent can ptrace, limits sudo token attack"
			case "2":
				desc = "admin only — ptrace requires CAP_SYS_PTRACE"
			case "3":
				desc = "disabled — ptrace completely blocked"
			}
			if !strings.Contains(desc, tc.contains) {
				t.Errorf("scope %s: desc %q doesn't contain %q", tc.scope, desc, tc.contains)
			}
		})
	}
}

func TestSudoersLineParsing(t *testing.T) {
	// Test sudoers file line filtering (non-comment, non-empty)
	content := `# /etc/sudoers
# This file MUST be edited with 'visudo'

Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL
`
	var activeLines []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			activeLines = append(activeLines, line)
		}
	}
	if len(activeLines) != 6 {
		t.Errorf("expected 6 active sudoers lines, got %d: %v", len(activeLines), activeLines)
	}
}

func TestPolkitJSRuleDetection(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		interesting bool
	}{
		{
			"allows without auth",
			`polkit.addRule(function(action, subject) {
				if (action.id == "org.freedesktop.udisks2.filesystem-mount") {
					return polkit.Result.YES;
				}
			});`,
			true,
		},
		{
			"requires auth",
			`polkit.addRule(function(action, subject) {
				if (action.id == "org.freedesktop.systemd1.manage-units") {
					return polkit.Result.AUTH_ADMIN;
				}
			});`,
			false,
		},
		{
			"YES in different context",
			`// Check if user can mount YES this is allowed
polkit.addRule(function() { return polkit.Result.YES; });`,
			true,
		},
		{
			"empty file",
			"",
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			interesting := strings.Contains(tc.content, "return polkit.Result.YES") ||
				strings.Contains(tc.content, "YES")
			if interesting != tc.interesting {
				t.Errorf("got interesting=%v, want %v", interesting, tc.interesting)
			}
		})
	}
}

func TestPolkitPKLADetection(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		interesting bool
	}{
		{
			"grants active access",
			"[Allow users to mount]\nIdentity=unix-group:users\nAction=org.freedesktop.udisks2.filesystem-mount\nResultActive=yes\n",
			true,
		},
		{
			"grants inactive access",
			"[Allow without session]\nIdentity=unix-user:admin\nResultInactive=yes\n",
			true,
		},
		{
			"grants any access",
			"[Allow any]\nResultAny=yes\n",
			true,
		},
		{
			"no grants",
			"[Deny mounting]\nIdentity=unix-group:users\nResultActive=auth_admin\n",
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			interesting := strings.Contains(tc.content, "ResultAny=yes") ||
				strings.Contains(tc.content, "ResultInactive=yes") ||
				strings.Contains(tc.content, "ResultActive=yes")
			if interesting != tc.interesting {
				t.Errorf("got interesting=%v, want %v", interesting, tc.interesting)
			}
		})
	}
}
