package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSecurityInfoName(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	if cmd.Name() != "security-info" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "security-info")
	}
}

func TestSecurityInfoDescription(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestSecurityInfoExecute(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
	if !strings.Contains(result.Output, "Security Posture Report") {
		t.Error("Output should contain report header")
	}
}

func TestSecurityInfoLinux(t *testing.T) {
	controls := securityInfoLinux()
	if len(controls) == 0 {
		t.Error("Should return at least one security control")
	}
	// Should check SELinux, AppArmor, and ASLR at minimum
	names := make(map[string]bool)
	for _, ctl := range controls {
		names[ctl.Name] = true
	}
	if !names["SELinux"] && !names["AppArmor"] {
		t.Error("Should check at least SELinux or AppArmor")
	}
}

func TestSecurityInfoOutputFormat(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)

	// Should have summary line
	if !strings.Contains(result.Output, "security controls active") {
		t.Error("Output should contain security controls summary")
	}
}

func TestReadFileQuiet(t *testing.T) {
	// Test with a file that exists
	content := readFileQuiet("/proc/self/status")
	if content == "" {
		t.Error("readFileQuiet should read /proc/self/status")
	}

	// Test with nonexistent file
	content = readFileQuiet("/nonexistent/path/xyz")
	if content != "" {
		t.Error("readFileQuiet should return empty for nonexistent files")
	}
}

func TestSecurityInfoWindowsNativeStub(t *testing.T) {
	// On non-Windows, the stub should return nil
	result := securityInfoWindowsNative()
	if result != nil {
		t.Errorf("securityInfoWindowsNative() on non-Windows should return nil, got %v", result)
	}
}

func TestSecurityInfoLinuxSELinux(t *testing.T) {
	controls := securityInfoLinux()
	// Should always have an SELinux entry (either from sysfs, getenforce, or "not found")
	found := false
	for _, ctl := range controls {
		if ctl.Name == "SELinux" {
			found = true
			// Status should be one of the expected values
			switch ctl.Status {
			case "enabled", "warning", "disabled", "not found":
				// valid
			default:
				t.Errorf("SELinux status = %q, unexpected value", ctl.Status)
			}
		}
	}
	if !found {
		t.Error("securityInfoLinux should include SELinux check")
	}
}

func TestSecurityInfoLinuxASLR(t *testing.T) {
	controls := securityInfoLinux()
	found := false
	for _, ctl := range controls {
		if ctl.Name == "ASLR" {
			found = true
			if ctl.Status != "enabled" && ctl.Status != "disabled" {
				t.Errorf("ASLR status = %q, expected enabled or disabled", ctl.Status)
			}
		}
	}
	if !found {
		t.Error("securityInfoLinux should include ASLR check")
	}
}

func TestSecurityInfoLinuxAppArmor(t *testing.T) {
	controls := securityInfoLinux()
	found := false
	for _, ctl := range controls {
		if ctl.Name == "AppArmor" {
			found = true
		}
	}
	if !found {
		t.Error("securityInfoLinux should include AppArmor check")
	}
}

// --- parseSshdConfig tests ---

func TestParseSshdConfig_Defaults(t *testing.T) {
	port, permitRoot := parseSshdConfig("")
	if port != "22" {
		t.Errorf("default port = %q, want %q", port, "22")
	}
	if permitRoot != "unknown" {
		t.Errorf("default permitRoot = %q, want %q", permitRoot, "unknown")
	}
}

func TestParseSshdConfig_CustomPort(t *testing.T) {
	config := "Port 2222\nPermitRootLogin no"
	port, permitRoot := parseSshdConfig(config)
	if port != "2222" {
		t.Errorf("port = %q, want %q", port, "2222")
	}
	if permitRoot != "no" {
		t.Errorf("permitRoot = %q, want %q", permitRoot, "no")
	}
}

func TestParseSshdConfig_ProhibitPassword(t *testing.T) {
	config := "PermitRootLogin prohibit-password"
	_, permitRoot := parseSshdConfig(config)
	if permitRoot != "prohibit-password" {
		t.Errorf("permitRoot = %q, want %q", permitRoot, "prohibit-password")
	}
}

func TestParseSshdConfig_CommentsIgnored(t *testing.T) {
	config := "# Port 9999\n#PermitRootLogin yes\nPort 22\nPermitRootLogin no"
	port, permitRoot := parseSshdConfig(config)
	if port != "22" {
		t.Errorf("port = %q, want %q (comments not ignored)", port, "22")
	}
	if permitRoot != "no" {
		t.Errorf("permitRoot = %q, want %q (comments not ignored)", permitRoot, "no")
	}
}

func TestParseSshdConfig_EmptyLines(t *testing.T) {
	config := "\n\nPort 443\n\n\nPermitRootLogin yes\n\n"
	port, permitRoot := parseSshdConfig(config)
	if port != "443" {
		t.Errorf("port = %q, want %q", port, "443")
	}
	if permitRoot != "yes" {
		t.Errorf("permitRoot = %q, want %q", permitRoot, "yes")
	}
}

func TestParseSshdConfig_CaseInsensitive(t *testing.T) {
	config := "port 8022\npermitRootLogin Yes"
	port, permitRoot := parseSshdConfig(config)
	if port != "8022" {
		t.Errorf("port = %q, want %q", port, "8022")
	}
	if permitRoot != "Yes" {
		t.Errorf("permitRoot = %q, want %q", permitRoot, "Yes")
	}
}

func TestParseSshdConfig_LastValueWins(t *testing.T) {
	config := "Port 22\nPort 2222\nPermitRootLogin yes\nPermitRootLogin no"
	port, permitRoot := parseSshdConfig(config)
	if port != "2222" {
		t.Errorf("port = %q, want %q (last value should win)", port, "2222")
	}
	if permitRoot != "no" {
		t.Errorf("permitRoot = %q, want %q (last value should win)", permitRoot, "no")
	}
}

func TestParseSshdConfig_WithExtraWhitespace(t *testing.T) {
	config := "  Port   3333  \n  PermitRootLogin   without-password  "
	port, permitRoot := parseSshdConfig(config)
	if port != "3333" {
		t.Errorf("port = %q, want %q", port, "3333")
	}
	if permitRoot != "without-password" {
		t.Errorf("permitRoot = %q, want %q", permitRoot, "without-password")
	}
}

func TestParseSshdConfig_RealisticConfig(t *testing.T) {
	config := `# This is the sshd_config
# See sshd_config(5)

#Port 22
#AddressFamily any
Port 22
#ListenAddress 0.0.0.0

# Authentication:
#LoginGraceTime 2m
PermitRootLogin prohibit-password
#StrictModes yes
MaxAuthTries 3

PubkeyAuthentication yes
PasswordAuthentication no
`
	port, permitRoot := parseSshdConfig(config)
	if port != "22" {
		t.Errorf("port = %q, want %q", port, "22")
	}
	if permitRoot != "prohibit-password" {
		t.Errorf("permitRoot = %q, want %q", permitRoot, "prohibit-password")
	}
}

func TestSecurityInfoLinuxNewControls(t *testing.T) {
	controls := securityInfoLinux()
	names := make(map[string]bool)
	for _, ctl := range controls {
		names[ctl.Name] = true
	}

	// kptr_restrict should be present on modern Linux
	if !names["kptr_restrict"] {
		t.Log("kptr_restrict not detected (may not be available on this kernel)")
	}

	// dmesg_restrict should be present on modern Linux
	if !names["dmesg_restrict"] {
		t.Log("dmesg_restrict not detected (may not be available on this kernel)")
	}

	// LSM Stack should be present if /sys/kernel/security/lsm is readable
	lsm := readFileQuiet("/sys/kernel/security/lsm")
	if lsm != "" && !names["LSM Stack"] {
		t.Error("LSM Stack should be reported when /sys/kernel/security/lsm is readable")
	}

	// Unprivileged BPF restriction should be present on modern kernels
	bpf := readFileQuiet("/proc/sys/kernel/unprivileged_bpf_disabled")
	if bpf != "" && !names["Unprivileged BPF"] {
		t.Error("Unprivileged BPF should be reported when sysctl is readable")
	}
}

// --- LD_PRELOAD Detection Tests ---

func TestCheckLDPreload_NoPreload(t *testing.T) {
	// When LD_PRELOAD is not set, should report "not found"
	controls := checkLDPreload()
	foundNotFound := false
	for _, c := range controls {
		if c.Name == "LD_PRELOAD" && c.Status == "not found" {
			foundNotFound = true
		}
	}
	// On clean test environment, expect either "not found" or actual preload
	if len(controls) == 0 {
		t.Error("checkLDPreload should return at least one control")
	}
	_ = foundNotFound // may or may not be set depending on test env
}

func TestCheckLDPreload_LdSoPreloadFile(t *testing.T) {
	// Test that /etc/ld.so.preload is checked (file may or may not exist)
	controls := checkLDPreload()
	// Should not panic or error regardless of file existence
	for _, c := range controls {
		if c.Name == "" || c.Status == "" {
			t.Errorf("control has empty fields: %+v", c)
		}
	}
}

func TestCheckLDPreload_ReturnsValidControls(t *testing.T) {
	controls := checkLDPreload()
	validStatuses := map[string]bool{"warning": true, "not found": true, "enabled": true, "info": true}
	for _, c := range controls {
		if !validStatuses[c.Status] {
			t.Errorf("unexpected status %q for %s", c.Status, c.Name)
		}
	}
}

// --- eBPF Monitoring Detection Tests ---

func TestCheckEBPFMonitoring_ReturnsControls(t *testing.T) {
	controls := checkEBPFMonitoring()
	if len(controls) == 0 {
		t.Error("checkEBPFMonitoring should return at least one control")
	}
}

func TestCheckEBPFMonitoring_BPFJITDetected(t *testing.T) {
	// BPF JIT should be detected on modern kernels
	bpfJIT := readFileQuiet("/proc/sys/net/core/bpf_jit_enable")
	if bpfJIT == "" {
		t.Skip("BPF JIT sysctl not available on this kernel")
	}
	controls := checkEBPFMonitoring()
	found := false
	for _, c := range controls {
		if c.Name == "BPF JIT" {
			found = true
			if c.Status != "enabled" && c.Status != "disabled" {
				t.Errorf("BPF JIT status should be enabled or disabled, got %q", c.Status)
			}
		}
	}
	if !found {
		t.Error("BPF JIT should be detected when sysctl is readable")
	}
}

func TestCheckEBPFMonitoring_ValidStatuses(t *testing.T) {
	controls := checkEBPFMonitoring()
	validStatuses := map[string]bool{
		"enabled": true, "disabled": true, "warning": true, "not found": true, "info": true,
	}
	for _, c := range controls {
		if !validStatuses[c.Status] {
			t.Errorf("unexpected status %q for %s", c.Status, c.Name)
		}
	}
}

func TestCheckEBPFMonitoring_NoEmptyFields(t *testing.T) {
	controls := checkEBPFMonitoring()
	for _, c := range controls {
		if c.Name == "" {
			t.Error("control Name must not be empty")
		}
		if c.Status == "" {
			t.Errorf("control %q has empty Status", c.Name)
		}
	}
}

// --- Integration: full securityInfoLinux includes new checks ---

func TestSecurityInfoLinux_IncludesLDPreload(t *testing.T) {
	controls := securityInfoLinux()
	found := false
	for _, c := range controls {
		if c.Name == "LD_PRELOAD" || c.Name == "ld.so.preload" || c.Name == "LD_AUDIT" {
			found = true
			break
		}
	}
	if !found {
		t.Error("securityInfoLinux should include LD_PRELOAD check")
	}
}

func TestSecurityInfoLinux_IncludesEBPF(t *testing.T) {
	controls := securityInfoLinux()
	found := false
	for _, c := range controls {
		if strings.Contains(c.Name, "BPF") || strings.Contains(c.Name, "eBPF") ||
			strings.Contains(c.Name, "kprobe") || strings.Contains(c.Name, "Tracepoint") {
			found = true
			break
		}
	}
	if !found {
		t.Error("securityInfoLinux should include eBPF monitoring check")
	}
}
