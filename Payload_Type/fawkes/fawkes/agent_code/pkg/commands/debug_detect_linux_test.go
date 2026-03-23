//go:build linux

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCheckTracerPid(t *testing.T) {
	result := checkTracerPid()
	if result.Name == "" {
		t.Error("expected non-empty check name")
	}
	if !strings.Contains(result.Name, "TracerPid") {
		t.Errorf("expected TracerPid in name, got %q", result.Name)
	}
	// In CI (not being debugged), TracerPid should be 0 → CLEAN
	if result.Status != "CLEAN" {
		t.Logf("TracerPid check: %s — %s", result.Status, result.Details)
	}
}

func TestCheckLdPreload_Default(t *testing.T) {
	result := checkLdPreload()
	if result.Name != "LD_PRELOAD" {
		t.Errorf("expected name 'LD_PRELOAD', got %q", result.Name)
	}
	// In CI, LD_PRELOAD should not be set
	if result.Status != "CLEAN" {
		t.Logf("LD_PRELOAD: %s — %s", result.Status, result.Details)
	}
}

func TestCheckLdPreload_Set(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/test.so")
	result := checkLdPreload()
	if result.Status != "WARNING" {
		t.Errorf("expected WARNING when LD_PRELOAD set, got %q", result.Status)
	}
	if !strings.Contains(result.Details, "/tmp/test.so") {
		t.Errorf("expected LD_PRELOAD value in details, got %q", result.Details)
	}
}

func TestRunPlatformDebugChecks(t *testing.T) {
	checks := runPlatformDebugChecks()
	if len(checks) < 8 {
		t.Errorf("expected at least 8 checks, got %d", len(checks))
	}
	// Verify each check has a name and status
	for i, c := range checks {
		if c.Name == "" {
			t.Errorf("check[%d] has empty name", i)
		}
		if c.Status == "" {
			t.Errorf("check[%d] %q has empty status", i, c.Name)
		}
	}
}

func TestCheckProcMaps(t *testing.T) {
	result := checkProcMaps()
	if !strings.Contains(result.Name, "Memory Maps") {
		t.Errorf("expected 'Memory Maps' in name, got %q", result.Name)
	}
	// In normal CI, should be CLEAN (no frida/valgrind)
	if result.Status == "ERROR" {
		t.Errorf("unexpected error: %s", result.Details)
	}
	if result.Status == "CLEAN" && !strings.Contains(result.Details, "mappings") {
		t.Errorf("CLEAN status should report mapping count, got %q", result.Details)
	}
}

func TestCheckProcStatus(t *testing.T) {
	result := checkProcStatus()
	if !strings.Contains(result.Name, "Process Status") {
		t.Errorf("expected 'Process Status' in name, got %q", result.Name)
	}
	// Should not error on a normal system
	if result.Status == "ERROR" {
		t.Errorf("unexpected error: %s", result.Details)
	}
}

func TestCheckSandboxIndicators(t *testing.T) {
	result := checkSandboxIndicators()
	if !strings.Contains(result.Name, "VM/Sandbox") {
		t.Errorf("expected 'VM/Sandbox' in name, got %q", result.Name)
	}
	// Status should be valid
	switch result.Status {
	case "CLEAN", "WARNING":
		// expected
	default:
		t.Errorf("unexpected status %q: %s", result.Status, result.Details)
	}
}

func TestCheckProcMaps_NoInstrumentation(t *testing.T) {
	// In a normal Go test, there should be no frida/valgrind in memory maps
	result := checkProcMaps()
	if result.Status == "DETECTED" {
		t.Logf("Instrumentation detected (may be expected in some CI): %s", result.Details)
	}
}

func TestCheckSandboxIndicators_VMDetection(t *testing.T) {
	// On CI runners (often VMs), this may detect hypervisor flag
	result := checkSandboxIndicators()
	if result.Status == "WARNING" {
		t.Logf("VM/sandbox indicators found (expected on CI): %s", result.Details)
	}
}

// --- Pure function tests for extracted helpers ---

func TestScanMapsForInstrumentation_Clean(t *testing.T) {
	data := `55d4f2e00000-55d4f2e01000 r-xp 00000000 08:01 1234 /usr/bin/myapp
7f8c12345000-7f8c12346000 r-xp 00000000 08:01 5678 /lib/x86_64-linux-gnu/libc.so.6
7f8c12400000-7f8c12401000 r-xp 00000000 08:01 9012 /lib/x86_64-linux-gnu/libpthread.so.0`
	found := scanMapsForInstrumentation(data)
	if len(found) != 0 {
		t.Errorf("expected no findings for clean maps, got %v", found)
	}
}

func TestScanMapsForInstrumentation_Frida(t *testing.T) {
	data := `55d4f2e00000-55d4f2e01000 r-xp 00000000 08:01 1234 /usr/bin/myapp
7f8c12345000-7f8c12346000 r-xp 00000000 08:01 5678 /tmp/frida-agent-64.so
7f8c12400000-7f8c12401000 r-xp 00000000 08:01 9012 /lib/libc.so.6`
	found := scanMapsForInstrumentation(data)
	if len(found) != 1 || found[0] != "Frida (dynamic instrumentation)" {
		t.Errorf("expected Frida detection, got %v", found)
	}
}

func TestScanMapsForInstrumentation_Valgrind(t *testing.T) {
	data := `7f8c12345000-7f8c12346000 r-xp 00000000 08:01 5678 /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so`
	found := scanMapsForInstrumentation(data)
	if len(found) != 1 || found[0] != "Valgrind (memory analysis)" {
		t.Errorf("expected Valgrind detection, got %v", found)
	}
}

func TestScanMapsForInstrumentation_MultipleSanitizers(t *testing.T) {
	data := `7f8c123-7f8c124 r-xp 08:01 1234 /usr/lib/gcc/x86_64-linux-gnu/12/libasan.so.6
7f8c125-7f8c126 r-xp 08:01 5678 /usr/lib/gcc/x86_64-linux-gnu/12/libtsan.so.2`
	found := scanMapsForInstrumentation(data)
	if len(found) != 2 {
		t.Errorf("expected 2 findings, got %d: %v", len(found), found)
	}
}

func TestScanMapsForInstrumentation_Deduplicates(t *testing.T) {
	data := `7f8c123-7f8c124 r-xp 08:01 1234 /tmp/frida-agent.so
7f8c125-7f8c126 r--p 08:01 1234 /tmp/frida-agent.so
7f8c127-7f8c128 rw-p 08:01 1234 /tmp/frida-agent.so`
	found := scanMapsForInstrumentation(data)
	if len(found) != 1 {
		t.Errorf("expected deduplicated to 1, got %d: %v", len(found), found)
	}
}

func TestScanMapsForInstrumentation_CaseInsensitive(t *testing.T) {
	data := `7f8c123-7f8c124 r-xp 08:01 1234 /tmp/FRIDA-Agent.SO`
	found := scanMapsForInstrumentation(data)
	if len(found) != 1 {
		t.Errorf("expected case-insensitive match, got %v", found)
	}
}

func TestScanMapsForInstrumentation_IntelPin(t *testing.T) {
	data := `7f8c123-7f8c124 r-xp 08:01 1234 /opt/intel/pin/source/tools/ManualExamples/obj-intel64/inscount0.so`
	found := scanMapsForInstrumentation(data)
	if len(found) != 1 || found[0] != "Intel Pin (binary instrumentation)" {
		t.Errorf("expected Intel Pin detection, got %v", found)
	}
}

func TestScanMapsForInstrumentation_DynamoRIO(t *testing.T) {
	data := `7f8c123-7f8c124 r-xp 08:01 1234 /home/user/dynamorio/build/lib64/release/libdynamorio.so.10.0`
	found := scanMapsForInstrumentation(data)
	if len(found) != 1 || found[0] != "DynamoRIO (binary instrumentation)" {
		t.Errorf("expected DynamoRIO detection, got %v", found)
	}
}

func TestScanMapsForInstrumentation_Empty(t *testing.T) {
	found := scanMapsForInstrumentation("")
	if len(found) != 0 {
		t.Errorf("expected no findings for empty data, got %v", found)
	}
}

func TestParseProcStatusWarnings_Clean(t *testing.T) {
	data := `Name:	myapp
Seccomp:	0
CapEff:	000001ffffffffff
TracerPid:	0`
	warnings := parseProcStatusWarnings(data)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for clean status, got %v", warnings)
	}
}

func TestParseProcStatusWarnings_SeccompStrict(t *testing.T) {
	data := `Name:	myapp
Seccomp:	1
CapEff:	000001ffffffffff`
	warnings := parseProcStatusWarnings(data)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "strict") {
		t.Errorf("expected strict mode warning, got %q", warnings[0])
	}
}

func TestParseProcStatusWarnings_SeccompFilter(t *testing.T) {
	data := `Name:	myapp
Seccomp:	2
CapEff:	000001ffffffffff`
	warnings := parseProcStatusWarnings(data)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "filter") {
		t.Errorf("expected filter mode warning, got %q", warnings[0])
	}
}

func TestParseProcStatusWarnings_ZeroCaps(t *testing.T) {
	data := `Name:	myapp
Seccomp:	0
CapEff:	0000000000000000`
	warnings := parseProcStatusWarnings(data)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for zero caps, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "Zero effective capabilities") {
		t.Errorf("expected zero capabilities warning, got %q", warnings[0])
	}
}

func TestParseProcStatusWarnings_BothSeccompAndCaps(t *testing.T) {
	data := `Name:	container
Seccomp:	2
CapEff:	0000000000000000`
	warnings := parseProcStatusWarnings(data)
	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestParseProcStatusWarnings_Empty(t *testing.T) {
	warnings := parseProcStatusWarnings("")
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for empty data, got %v", warnings)
	}
}

func TestClassifyDMIProduct_VirtualBox(t *testing.T) {
	if got := classifyDMIProduct("VirtualBox"); got != "VirtualBox (DMI)" {
		t.Errorf("got %q, want VirtualBox (DMI)", got)
	}
}

func TestClassifyDMIProduct_VMware(t *testing.T) {
	if got := classifyDMIProduct("VMware Virtual Platform"); got != "VMware (DMI)" {
		t.Errorf("got %q, want VMware (DMI)", got)
	}
}

func TestClassifyDMIProduct_KVM(t *testing.T) {
	if got := classifyDMIProduct("KVM"); got != "KVM/QEMU (DMI)" {
		t.Errorf("got %q, want KVM/QEMU (DMI)", got)
	}
}

func TestClassifyDMIProduct_QEMU(t *testing.T) {
	if got := classifyDMIProduct("QEMU Standard PC"); got != "KVM/QEMU (DMI)" {
		t.Errorf("got %q, want KVM/QEMU (DMI)", got)
	}
}

func TestClassifyDMIProduct_HyperV(t *testing.T) {
	if got := classifyDMIProduct("Virtual Machine"); got != "Hyper-V (DMI)" {
		t.Errorf("got %q, want Hyper-V (DMI)", got)
	}
	if got := classifyDMIProduct("Hyper-V UEFI Release v4.1"); got != "Hyper-V (DMI)" {
		t.Errorf("got %q, want Hyper-V (DMI)", got)
	}
}

func TestClassifyDMIProduct_Xen(t *testing.T) {
	if got := classifyDMIProduct("Xen HVM domU"); got != "Xen (DMI)" {
		t.Errorf("got %q, want Xen (DMI)", got)
	}
}

func TestClassifyDMIProduct_Physical(t *testing.T) {
	if got := classifyDMIProduct("ThinkPad T480"); got != "" {
		t.Errorf("expected empty for physical hardware, got %q", got)
	}
}

func TestClassifyDMIProduct_Empty(t *testing.T) {
	if got := classifyDMIProduct(""); got != "" {
		t.Errorf("expected empty for empty input, got %q", got)
	}
}

func TestClassifyDMIProduct_CaseInsensitive(t *testing.T) {
	if got := classifyDMIProduct("VIRTUALBOX"); got != "VirtualBox (DMI)" {
		t.Errorf("expected case-insensitive match, got %q", got)
	}
}

// --- eBPF, Auditd, Ptrace Scope tests (Session 216) ---

func TestCheckEBPF(t *testing.T) {
	result := checkEBPF()
	if !strings.Contains(result.Name, "eBPF") {
		t.Errorf("expected 'eBPF' in name, got %q", result.Name)
	}
	// Status should be valid
	switch result.Status {
	case "CLEAN", "DETECTED":
		// expected
	default:
		t.Errorf("unexpected status %q: %s", result.Status, result.Details)
	}
}

func TestCheckAuditd(t *testing.T) {
	result := checkAuditd()
	if !strings.Contains(result.Name, "Audit") {
		t.Errorf("expected 'Audit' in name, got %q", result.Name)
	}
	switch result.Status {
	case "CLEAN", "WARNING":
		// expected
	default:
		t.Errorf("unexpected status %q: %s", result.Status, result.Details)
	}
}

func TestCheckPtraceScope(t *testing.T) {
	result := checkPtraceScope()
	if !strings.Contains(result.Name, "Ptrace") {
		t.Errorf("expected 'Ptrace' in name, got %q", result.Name)
	}
	switch result.Status {
	case "CLEAN", "WARNING", "DETECTED":
		// expected — depends on system config
	default:
		t.Errorf("unexpected status %q: %s", result.Status, result.Details)
	}
	// Details should contain ptrace_scope value or Yama info
	if !strings.Contains(result.Details, "ptrace") && !strings.Contains(result.Details, "Yama") {
		t.Errorf("expected ptrace info in details, got %q", result.Details)
	}
}

func TestRunPlatformDebugChecks_IncludesNewChecks(t *testing.T) {
	checks := runPlatformDebugChecks()
	// Should now have 8 checks (was 5, added 3)
	if len(checks) < 8 {
		t.Errorf("expected at least 8 checks, got %d", len(checks))
	}
	// Verify new check names present
	names := make(map[string]bool)
	for _, c := range checks {
		names[c.Name] = true
	}
	for _, expected := range []string{"eBPF Monitoring", "Audit Framework (auditd)", "Ptrace Scope"} {
		if !names[expected] {
			t.Errorf("missing check %q in platform checks", expected)
		}
	}
}

func TestDebugDetect_IncludesNewChecks(t *testing.T) {
	cmd := &DebugDetectCommand{}
	task := structs.NewTask("t", "debug-detect", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	for _, name := range []string{"eBPF", "Audit", "Ptrace"} {
		if !strings.Contains(result.Output, name) {
			t.Errorf("expected %q in output, got: %s", name, result.Output)
		}
	}
}
