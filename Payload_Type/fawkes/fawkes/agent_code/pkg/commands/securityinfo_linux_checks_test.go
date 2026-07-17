//go:build linux

package commands

import (
	"os"
	"strings"
	"testing"
)

func findControlByName(controls []secControl, name string) *secControl {
	for i := range controls {
		if controls[i].Name == name {
			return &controls[i]
		}
	}
	return nil
}

// --- checkMACControls: Seccomp detection ---

func TestCheckMACControls_SeccompFromProcStatus(t *testing.T) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skip("cannot read /proc/self/status")
	}
	hasSeccomp := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			hasSeccomp = true
			break
		}
	}
	if !hasSeccomp {
		t.Skip("kernel doesn't expose Seccomp in /proc/self/status")
	}

	controls := checkMACControls()
	c := findControlByName(controls, "Seccomp")
	if c == nil {
		t.Error("Seccomp control should be present when /proc/self/status has Seccomp line")
	} else if c.Status != "enabled" && c.Status != "disabled" {
		t.Errorf("Seccomp status should be enabled or disabled, got %q", c.Status)
	}
}

func TestCheckMACControls_SELinuxAlwaysReported(t *testing.T) {
	controls := checkMACControls()
	c := findControlByName(controls, "SELinux")
	if c == nil {
		t.Fatal("SELinux control should always be present (enabled, disabled, or not found)")
	}
	validStatuses := map[string]bool{"enabled": true, "disabled": true, "warning": true, "not found": true}
	if !validStatuses[c.Status] {
		t.Errorf("SELinux has unexpected status %q", c.Status)
	}
}

func TestCheckMACControls_AppArmorAlwaysReported(t *testing.T) {
	controls := checkMACControls()
	c := findControlByName(controls, "AppArmor")
	if c == nil {
		t.Fatal("AppArmor control should always be present")
	}
	validStatuses := map[string]bool{"enabled": true, "not found": true}
	if !validStatuses[c.Status] {
		t.Errorf("AppArmor has unexpected status %q", c.Status)
	}
}

// --- checkAuditAndFirewall ---

func TestCheckAuditAndFirewall_AuditAlwaysReported(t *testing.T) {
	controls := checkAuditAndFirewall()
	c := findControlByName(controls, "Linux Audit (auditd)")
	if c == nil {
		t.Fatal("auditd control should always be present")
	}
	if c.Status != "enabled" && c.Status != "not found" {
		t.Errorf("auditd should be enabled or not found, got %q", c.Status)
	}
}

func TestCheckAuditAndFirewall_AuditDetectionLogic(t *testing.T) {
	loginuid := readFileQuiet("/proc/self/loginuid")
	auditdPid := readFileQuiet("/var/run/auditd.pid")
	if auditdPid == "" {
		auditdPid = readFileQuiet("/run/auditd.pid")
	}

	expectEnabled := (loginuid != "" && strings.TrimSpace(loginuid) != "4294967295") || auditdPid != ""

	controls := checkAuditAndFirewall()
	c := findControlByName(controls, "Linux Audit (auditd)")
	if c == nil {
		t.Fatal("auditd control missing")
	}

	if expectEnabled {
		if c.Status != "enabled" {
			t.Errorf("expected auditd enabled (loginuid=%q, pid=%q), got status %q",
				strings.TrimSpace(loginuid), strings.TrimSpace(auditdPid), c.Status)
		}
		if auditdPid != "" && !strings.Contains(c.Details, "auditd running") {
			t.Error("details should mention auditd running when PID file exists")
		}
	} else if c.Status != "not found" {
		t.Errorf("expected auditd not found, got status %q", c.Status)
	}
}

// --- checkKernelHardening ---

func TestCheckKernelHardening_YamaPtraceScope(t *testing.T) {
	yama := readFileQuiet("/proc/sys/kernel/yama/ptrace_scope")
	if yama == "" {
		t.Skip("Yama ptrace scope not available")
	}

	controls := checkKernelHardening()
	c := findControlByName(controls, "YAMA ptrace")
	if c == nil {
		t.Fatal("YAMA ptrace control should be present when sysctl exists")
	}

	val := strings.TrimSpace(yama)
	switch val {
	case "0":
		if c.Status != "disabled" {
			t.Errorf("ptrace_scope=0 should be disabled, got %q", c.Status)
		}
		if !strings.Contains(c.Details, "any process") {
			t.Errorf("scope=0 details should mention 'any process', got: %s", c.Details)
		}
	case "1":
		if c.Status != "enabled" {
			t.Errorf("ptrace_scope=1 should be enabled, got %q", c.Status)
		}
		if !strings.Contains(c.Details, "parent-only") {
			t.Errorf("scope=1 details should mention 'parent-only', got: %s", c.Details)
		}
	case "2":
		if !strings.Contains(c.Details, "admin-only") {
			t.Errorf("scope=2 details should mention 'admin-only', got: %s", c.Details)
		}
	case "3":
		if !strings.Contains(c.Details, "no tracing") {
			t.Errorf("scope=3 details should mention 'no tracing', got: %s", c.Details)
		}
	}
}

func TestCheckKernelHardening_LSMSubModuleDetection(t *testing.T) {
	lsm := readFileQuiet("/sys/kernel/security/lsm")
	if lsm == "" {
		t.Skip("LSM stack not available")
	}

	controls := checkKernelHardening()
	modules := strings.TrimSpace(lsm)

	if strings.Contains(modules, "landlock") {
		lc := findControlByName(controls, "Landlock")
		if lc == nil {
			t.Error("Landlock should be reported when present in LSM stack")
		} else if lc.Status != "enabled" {
			t.Errorf("Landlock should be enabled, got %q", lc.Status)
		}
	}
	if strings.Contains(modules, "bpf") {
		bc := findControlByName(controls, "BPF LSM")
		if bc == nil {
			t.Error("BPF LSM should be reported when present in LSM stack")
		} else if bc.Status != "enabled" {
			t.Errorf("BPF LSM should be enabled, got %q", bc.Status)
		}
	}
	if strings.Contains(modules, "tomoyo") {
		tc := findControlByName(controls, "TOMOYO")
		if tc == nil {
			t.Error("TOMOYO should be reported when present in LSM stack")
		} else if tc.Status != "enabled" {
			t.Errorf("TOMOYO should be enabled, got %q", tc.Status)
		}
	}
}

func TestCheckKernelHardening_DmesgRestrictValues(t *testing.T) {
	dmesg := readFileQuiet("/proc/sys/kernel/dmesg_restrict")
	if dmesg == "" {
		t.Skip("dmesg_restrict not available")
	}

	controls := checkKernelHardening()
	c := findControlByName(controls, "dmesg_restrict")
	if c == nil {
		t.Fatal("dmesg_restrict control should be present")
	}

	val := strings.TrimSpace(dmesg)
	if val == "1" {
		if c.Status != "enabled" {
			t.Errorf("dmesg_restrict=1 should be enabled, got %q", c.Status)
		}
		if !strings.Contains(c.Details, "CAP_SYSLOG") {
			t.Errorf("enabled details should mention CAP_SYSLOG, got: %s", c.Details)
		}
	} else if c.Status != "disabled" {
		t.Errorf("dmesg_restrict=%s should be disabled, got %q", val, c.Status)
	}
}

func TestCheckKernelHardening_KernelLockdown(t *testing.T) {
	lockdown := readFileQuiet("/sys/kernel/security/lockdown")
	if lockdown == "" {
		t.Skip("kernel lockdown not available")
	}

	controls := checkKernelHardening()
	c := findControlByName(controls, "Kernel Lockdown")
	if c == nil {
		t.Fatal("Kernel Lockdown should be present when sysfs exists")
	}
	if c.Status != "info" {
		t.Errorf("Kernel Lockdown should have info status, got %q", c.Status)
	}
}

// --- checkDiskEncryption ---

func TestCheckDiskEncryption_StructureAndCounting(t *testing.T) {
	entries, err := os.ReadDir("/dev/mapper")
	if err != nil {
		t.Skip("/dev/mapper not available")
	}
	var expected int
	for _, e := range entries {
		name := e.Name()
		if name != "control" && !strings.HasPrefix(name, ".") {
			expected++
		}
	}

	controls := checkDiskEncryption()

	if expected > 0 {
		c := findControlByName(controls, "dm-crypt/LUKS")
		if c == nil {
			t.Fatal("dm-crypt/LUKS control should be present when devices exist")
		}
		if c.Status != "enabled" {
			t.Errorf("expected enabled, got %q", c.Status)
		}
		if !strings.Contains(c.Details, "device(s)") {
			t.Errorf("details should mention device count, got: %s", c.Details)
		}
	} else if len(controls) != 0 {
		t.Error("should return empty when no dm-crypt devices")
	}
}

func TestCheckDiskEncryption_FiltersDotAndControl(t *testing.T) {
	entries, err := os.ReadDir("/dev/mapper")
	if err != nil {
		t.Skip("/dev/mapper not available")
	}
	controls := checkDiskEncryption()
	for _, c := range controls {
		if strings.Contains(c.Details, "control") {
			for _, e := range entries {
				if e.Name() == "control" {
					t.Error("should filter out the 'control' device from listing")
				}
			}
		}
	}
}

// --- checkLDPreload (complementing existing tests) ---

func TestCheckLDPreload_BothEnvVarsSet(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/inject.so")
	t.Setenv("LD_AUDIT", "/tmp/audit.so")

	controls := checkLDPreload()

	preload := findControlByName(controls, "LD_PRELOAD")
	if preload == nil || preload.Status != "warning" {
		t.Error("LD_PRELOAD should be warning when env var is set")
	} else if !strings.Contains(preload.Details, "/tmp/inject.so") {
		t.Errorf("LD_PRELOAD details should contain path, got: %s", preload.Details)
	}

	audit := findControlByName(controls, "LD_AUDIT")
	if audit == nil || audit.Status != "warning" {
		t.Error("LD_AUDIT should be warning when env var is set")
	} else if !strings.Contains(audit.Details, "/tmp/audit.so") {
		t.Errorf("LD_AUDIT details should contain path, got: %s", audit.Details)
	}
}

func TestCheckLDPreload_NotFoundFallback(t *testing.T) {
	t.Setenv("LD_PRELOAD", "")
	t.Setenv("LD_AUDIT", "")

	controls := checkLDPreload()
	preload := findControlByName(controls, "LD_PRELOAD")
	if preload == nil {
		t.Fatal("LD_PRELOAD control should always be present")
	}
	if preload.Status == "warning" {
		t.Error("should not warn when LD_PRELOAD is empty")
	}
}

// --- checkEBPFMonitoring (complementing existing tests) ---

func TestCheckEBPFMonitoring_FallbackWhenNoWarnings(t *testing.T) {
	controls := checkEBPFMonitoring()
	hasKprobeWarning := false
	hasTracepointWarning := false
	hasEBPFToolWarning := false
	hasNoMonitorFallback := false

	for _, c := range controls {
		switch {
		case c.Name == "kprobe Events" && c.Status == "warning":
			hasKprobeWarning = true
		case c.Name == "Tracepoints" && c.Status == "warning":
			hasTracepointWarning = true
		case c.Name == "eBPF Monitor" && c.Status == "warning":
			hasEBPFToolWarning = true
		case c.Name == "eBPF Monitoring" && c.Status == "not found":
			hasNoMonitorFallback = true
		}
	}

	hasAnyWarning := hasKprobeWarning || hasTracepointWarning || hasEBPFToolWarning
	if !hasAnyWarning && !hasNoMonitorFallback {
		t.Error("should either have monitoring warnings or 'not found' fallback")
	}
	if hasAnyWarning && hasNoMonitorFallback {
		t.Error("should not have both monitoring warnings and 'not found' fallback")
	}
}

func TestCheckEBPFMonitoring_KnownToolMap(t *testing.T) {
	expected := []string{
		"tetragon", "falco", "tracee", "bpftrace", "sysdig",
		"cilium-agent", "hubble", "pulsar", "kubearmor", "inspektor-gadget",
	}
	controls := checkEBPFMonitoring()
	for _, c := range controls {
		if c.Name != "eBPF Monitor" {
			continue
		}
		matched := false
		for _, tool := range expected {
			if strings.Contains(strings.ToLower(c.Details), tool) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("eBPF Monitor control has unrecognized tool in details: %s", c.Details)
		}
	}
}

// --- Cross-cutting validation ---

func TestSecurityInfoLinux_NoDuplicateControlNames(t *testing.T) {
	controls := securityInfoLinux()
	seen := make(map[string]int)
	for _, c := range controls {
		seen[c.Name]++
	}
	for name, count := range seen {
		if name == "eBPF Monitor" {
			continue
		}
		if count > 1 {
			t.Errorf("control %q appears %d times (expected at most 1)", name, count)
		}
	}
}

func TestSecurityInfoLinux_EnabledControlsHaveDetails(t *testing.T) {
	controls := securityInfoLinux()
	for _, c := range controls {
		if c.Status == "enabled" && c.Details == "" {
			t.Errorf("control %q is enabled but has empty details", c.Name)
		}
		if c.Status == "warning" && c.Details == "" {
			t.Errorf("control %q is warning but has empty details", c.Name)
		}
	}
}
