package agentfunctions

import (
	"strings"
	"testing"
)

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

// --- generateProxyCSource tests ---

func TestGenerateProxyCSource_BasicStructure(t *testing.T) {
	shellcode := []byte{0x90, 0xCC, 0xC3}
	exports := []hijackExportEntry{
		{Ordinal: 1, Name: "GetFileVersionInfoA"},
	}
	src := generateProxyCSource(exports, "version_orig.dll", shellcode)

	if !strings.Contains(src, "#include <windows.h>") {
		t.Error("expected windows.h include")
	}
	if !strings.Contains(src, "0x90, 0xCC, 0xC3") {
		t.Error("expected shellcode bytes in array")
	}
	if !strings.Contains(src, "DllMain") {
		t.Error("expected DllMain entry point")
	}
	if !strings.Contains(src, "VirtualAlloc") {
		t.Error("expected VirtualAlloc for shellcode execution")
	}
	if !strings.Contains(src, "CreateThread") {
		t.Error("expected CreateThread for async execution")
	}
}

func TestGenerateProxyCSource_EmptyShellcode(t *testing.T) {
	src := generateProxyCSource(nil, "test.dll", []byte{})
	if !strings.Contains(src, "static unsigned char payload[]") {
		t.Error("expected payload array even when empty")
	}
	if !strings.Contains(src, "DllMain") {
		t.Error("expected DllMain")
	}
}

func TestGenerateProxyCSource_LargeShellcode(t *testing.T) {
	shellcode := make([]byte, 100)
	for i := range shellcode {
		shellcode[i] = byte(i % 256)
	}
	src := generateProxyCSource(nil, "test.dll", shellcode)
	if !strings.Contains(src, "0x00") {
		t.Error("expected first byte")
	}
	if !strings.Contains(src, "0x63") {
		t.Error("expected last byte (99 = 0x63)")
	}
}

// --- generateProxyDEFFile tests ---

func TestGenerateProxyDEFFile_NamedExports(t *testing.T) {
	exports := []hijackExportEntry{
		{Ordinal: 1, Name: "GetFileVersionInfoA"},
		{Ordinal: 2, Name: "GetFileVersionInfoW"},
		{Ordinal: 3, Name: "VerQueryValueA"},
	}
	def := generateProxyDEFFile(exports, "version_orig.dll")

	if !strings.HasPrefix(def, "EXPORTS\n") {
		t.Error("expected EXPORTS header")
	}
	if !strings.Contains(def, "GetFileVersionInfoA=version_orig.GetFileVersionInfoA @1") {
		t.Errorf("expected proxy export line, got:\n%s", def)
	}
	if !strings.Contains(def, "VerQueryValueA=version_orig.VerQueryValueA @3") {
		t.Error("expected third export")
	}
}

func TestGenerateProxyDEFFile_OrdinalOnly(t *testing.T) {
	exports := []hijackExportEntry{
		{Ordinal: 42, Name: ""},
	}
	def := generateProxyDEFFile(exports, "target.dll")

	if !strings.Contains(def, "noname_42=target.#42 @42 NONAME") {
		t.Errorf("expected NONAME ordinal export, got:\n%s", def)
	}
}

func TestGenerateProxyDEFFile_SkipsForwarders(t *testing.T) {
	exports := []hijackExportEntry{
		{Ordinal: 1, Name: "RealExport"},
		{Ordinal: 2, Name: "ForwardedExport", Forwarder: "ntdll.RtlMoveMemory"},
	}
	def := generateProxyDEFFile(exports, "test.dll")

	if strings.Contains(def, "ForwardedExport") {
		t.Error("forwarder exports should be skipped")
	}
	if !strings.Contains(def, "RealExport") {
		t.Error("real exports should be included")
	}
}

func TestGenerateProxyDEFFile_DLLSuffix(t *testing.T) {
	exports := []hijackExportEntry{
		{Ordinal: 1, Name: "Func1"},
	}
	def := generateProxyDEFFile(exports, "mylib.dll")

	if strings.Contains(def, "mylib.dll.Func1") {
		t.Error("should strip .dll suffix from renamed DLL name")
	}
	if !strings.Contains(def, "mylib.Func1") {
		t.Errorf("expected mylib.Func1, got:\n%s", def)
	}
}

func TestGenerateProxyDEFFile_Empty(t *testing.T) {
	def := generateProxyDEFFile(nil, "test.dll")
	if def != "EXPORTS\n" {
		t.Errorf("expected just header for empty exports, got %q", def)
	}
}
