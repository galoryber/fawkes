package agentfunctions

import (
	"testing"
)

func TestExtractWinRMExecutionInfo_Valid(t *testing.T) {
	input := "[*] WinRM admin@DC01:5985 (cmd, ntlm) — output follows"
	user, host, port, shell, ok := extractWinRMExecutionInfo(input)
	if !ok {
		t.Fatal("expected match")
	}
	if user != "admin" {
		t.Errorf("expected admin, got %q", user)
	}
	if host != "DC01" {
		t.Errorf("expected DC01, got %q", host)
	}
	if port != "5985" {
		t.Errorf("expected 5985, got %q", port)
	}
	if shell != "cmd" {
		t.Errorf("expected cmd, got %q", shell)
	}
}

func TestExtractWinRMExecutionInfo_PowerShell(t *testing.T) {
	input := "[*] WinRM DOMAIN\\jsmith@192.168.1.10:5986 (powershell, ntlm) — encrypted"
	user, host, port, shell, ok := extractWinRMExecutionInfo(input)
	if !ok {
		t.Fatal("expected match")
	}
	if user != "DOMAIN\\jsmith" {
		t.Errorf("expected DOMAIN\\jsmith, got %q", user)
	}
	if host != "192.168.1.10" {
		t.Errorf("expected 192.168.1.10, got %q", host)
	}
	if port != "5986" {
		t.Errorf("expected 5986, got %q", port)
	}
	if shell != "powershell" {
		t.Errorf("expected powershell, got %q", shell)
	}
}

func TestExtractWinRMExecutionInfo_NoMatch(t *testing.T) {
	_, _, _, _, ok := extractWinRMExecutionInfo("WinRM connection failed: timeout")
	if ok {
		t.Error("expected no match")
	}
}

func TestExtractWinRMExecutionInfo_Empty(t *testing.T) {
	_, _, _, _, ok := extractWinRMExecutionInfo("")
	if ok {
		t.Error("expected no match for empty input")
	}
}

func TestCountPrivilegeLines_Multiple(t *testing.T) {
	input := "SeDebugPrivilege\nSeImpersonatePrivilege\nSeBackupPrivilege\n"
	if count := countPrivilegeLines(input); count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

func TestCountPrivilegeLines_Single(t *testing.T) {
	input := "SeShutdownPrivilege\n"
	if count := countPrivilegeLines(input); count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}

func TestCountPrivilegeLines_Empty(t *testing.T) {
	if count := countPrivilegeLines(""); count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestCountPrivilegeLines_NoNewline(t *testing.T) {
	if count := countPrivilegeLines("SeDebugPrivilege"); count != 0 {
		t.Errorf("expected 0 (no trailing newline), got %d", count)
	}
}
