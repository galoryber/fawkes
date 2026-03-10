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
