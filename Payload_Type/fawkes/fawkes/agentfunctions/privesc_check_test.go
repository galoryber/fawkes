package agentfunctions

import "testing"

// --- analyzeWindowsPrivesc tests ---

func TestWindowsPrivesc_AlreadySystem(t *testing.T) {
	cmd, _, reason := analyzeWindowsPrivesc("some output", "4")
	if cmd != "" {
		t.Errorf("expected no command for SYSTEM, got %q", cmd)
	}
	if reason == "" {
		t.Error("expected a reason string")
	}
}

func TestWindowsPrivesc_HighIntegrity_WithDebug(t *testing.T) {
	output := `--- Token Privileges ---
SeDebugPrivilege   [Enabled]
SeBackupPrivilege  [Disabled]`
	cmd, params, _ := analyzeWindowsPrivesc(output, "3")
	if cmd != "getsystem" {
		t.Errorf("expected getsystem for high integrity, got %q", cmd)
	}
	if params != `{"technique":"steal"}` {
		t.Errorf("expected steal technique, got %q", params)
	}
}

func TestWindowsPrivesc_HighIntegrity_NoDebug(t *testing.T) {
	output := "--- Token Privileges ---\nSeBackupPrivilege  [Disabled]"
	cmd, params, _ := analyzeWindowsPrivesc(output, "3")
	if cmd != "getsystem" {
		t.Errorf("expected getsystem, got %q", cmd)
	}
	if params != `{"technique":"steal"}` {
		t.Errorf("expected steal technique, got %q", params)
	}
}

func TestWindowsPrivesc_MediumIntegrity_UACEnabled(t *testing.T) {
	output := "EnableLUA = 1\nConsentPromptBehavior = 5"
	cmd, params, _ := analyzeWindowsPrivesc(output, "2")
	if cmd != "uac-bypass" {
		t.Errorf("expected uac-bypass for medium integrity, got %q", cmd)
	}
	if params != `{"technique":"fodhelper"}` {
		t.Errorf("expected fodhelper technique, got %q", params)
	}
}

func TestWindowsPrivesc_MediumIntegrity_UACDisabled(t *testing.T) {
	output := "EnableLUA = 0\nUAC is disabled"
	cmd, _, reason := analyzeWindowsPrivesc(output, "2")
	if cmd != "getsystem" {
		t.Errorf("expected getsystem when UAC disabled, got %q", cmd)
	}
	if reason == "" {
		t.Error("expected a reason")
	}
}

func TestWindowsPrivesc_LowIntegrity(t *testing.T) {
	cmd, _, _ := analyzeWindowsPrivesc("some output", "1")
	if cmd != "" {
		t.Errorf("expected no command for low integrity, got %q", cmd)
	}
}

// --- analyzeLinuxPrivesc tests ---

func TestLinuxPrivesc_AlreadyRoot(t *testing.T) {
	cmd, _, reason := analyzeLinuxPrivesc("uid=0(root) gid=0(root)")
	if cmd != "" {
		t.Errorf("expected no command for root, got %q", cmd)
	}
	if reason == "" {
		t.Error("expected a reason")
	}
}

func TestLinuxPrivesc_SudoNopasswdAll(t *testing.T) {
	output := `--- Sudo Rules ---
(ALL) NOPASSWD: ALL`
	cmd, params, _ := analyzeLinuxPrivesc(output)
	if cmd != "getsystem" {
		t.Errorf("expected getsystem, got %q", cmd)
	}
	if params != `{"technique":"sudo"}` {
		t.Errorf("expected sudo technique, got %q", params)
	}
}

func TestLinuxPrivesc_SudoNopasswdPartial(t *testing.T) {
	output := `--- Sudo Rules ---
(root) NOPASSWD: /usr/bin/vim`
	cmd, _, _ := analyzeLinuxPrivesc(output)
	if cmd != "getsystem" {
		t.Errorf("expected getsystem for NOPASSWD rule, got %q", cmd)
	}
}

func TestLinuxPrivesc_SudoTokenReuse(t *testing.T) {
	output := `--- Sudo Token Reuse ---
sudo token reuse POSSIBLE (ptrace_scope=0, valid timestamp found)`
	cmd, _, _ := analyzeLinuxPrivesc(output)
	if cmd != "getsystem" {
		t.Errorf("expected getsystem for token reuse, got %q", cmd)
	}
}

func TestLinuxPrivesc_DockerGroup(t *testing.T) {
	output := `--- Docker Group ---
docker group: MEMBER`
	cmd, _, reason := analyzeLinuxPrivesc(output)
	if cmd != "" {
		t.Errorf("docker group should not auto-escalate, got %q", cmd)
	}
	if reason == "" {
		t.Error("expected reason about docker group")
	}
}

func TestLinuxPrivesc_NoVectors(t *testing.T) {
	output := "=== LINUX PRIVILEGE ESCALATION CHECK ===\n--- Sudo Rules ---\nNo sudo access"
	cmd, _, _ := analyzeLinuxPrivesc(output)
	if cmd != "" {
		t.Errorf("expected no command when no vectors, got %q", cmd)
	}
}

// --- analyzeMacOSPrivesc tests ---

func TestMacOSPrivesc_AlreadyRoot(t *testing.T) {
	cmd, _, _ := analyzeMacOSPrivesc("uid=0(root)")
	if cmd != "" {
		t.Errorf("expected no command for root, got %q", cmd)
	}
}

func TestMacOSPrivesc_SudoNopasswd(t *testing.T) {
	output := "--- Sudo Rules ---\nuser ALL=(ALL) NOPASSWD: ALL"
	cmd, params, _ := analyzeMacOSPrivesc(output)
	if cmd != "getsystem" {
		t.Errorf("expected getsystem, got %q", cmd)
	}
	if params != `{"technique":"sudo"}` {
		t.Errorf("expected sudo technique, got %q", params)
	}
}

func TestMacOSPrivesc_NoVectors(t *testing.T) {
	output := "=== MACOS PRIVILEGE ESCALATION CHECK ===\nNo writable paths"
	cmd, _, _ := analyzeMacOSPrivesc(output)
	if cmd != "getsystem" {
		t.Errorf("expected getsystem check fallback, got %q", cmd)
	}
}
