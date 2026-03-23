//go:build linux

package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// runPlatformDebugChecks runs Linux-specific anti-debug checks.
func runPlatformDebugChecks() []debugCheck {
	var checks []debugCheck

	checks = append(checks, checkTracerPid())
	checks = append(checks, checkLdPreload())
	checks = append(checks, checkProcMaps())
	checks = append(checks, checkProcStatus())
	checks = append(checks, checkSandboxIndicators())
	checks = append(checks, checkEBPF())
	checks = append(checks, checkAuditd())
	checks = append(checks, checkPtraceScope())

	return checks
}

// checkTracerPid reads /proc/self/status for TracerPid field.
// A non-zero TracerPid means a debugger (GDB, strace, ltrace) is attached via ptrace.
func checkTracerPid() debugCheck {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return debugCheck{Name: "TracerPid (/proc/self/status)", Status: "ERROR", Details: fmt.Sprintf("Failed to read: %v", err)}
	}
	defer structs.ZeroBytes(data) // opsec

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				pidStr := strings.TrimSpace(parts[1])
				pid, _ := strconv.Atoi(pidStr)
				if pid > 0 {
					return debugCheck{
						Name:    "TracerPid (/proc/self/status)",
						Status:  "DETECTED",
						Details: fmt.Sprintf("Traced by PID %d", pid),
					}
				}
				return debugCheck{Name: "TracerPid (/proc/self/status)", Status: "CLEAN", Details: "TracerPid: 0"}
			}
		}
	}

	return debugCheck{Name: "TracerPid (/proc/self/status)", Status: "ERROR", Details: "TracerPid field not found"}
}

// checkLdPreload checks for LD_PRELOAD environment variable which may indicate library injection/hooking.
func checkLdPreload() debugCheck {
	val := os.Getenv("LD_PRELOAD")
	if val != "" {
		return debugCheck{
			Name:    "LD_PRELOAD",
			Status:  "WARNING",
			Details: fmt.Sprintf("Set: %s", val),
		}
	}
	return debugCheck{Name: "LD_PRELOAD", Status: "CLEAN", Details: "Not set"}
}

// suspiciousLibPatterns maps library name patterns to their tool descriptions.
var suspiciousLibPatterns = []struct {
	pattern string
	tool    string
}{
	{"frida", "Frida (dynamic instrumentation)"},
	{"valgrind", "Valgrind (memory analysis)"},
	{"libasan", "AddressSanitizer"},
	{"libtsan", "ThreadSanitizer"},
	{"libubsan", "UndefinedBehaviorSanitizer"},
	{"libmsan", "MemorySanitizer"},
	{"pin/", "Intel Pin (binary instrumentation)"},
	{"dynamorio", "DynamoRIO (binary instrumentation)"},
	{"qbdi", "QBDI (instrumentation)"},
}

// scanMapsForInstrumentation scans memory map lines for suspicious libraries.
// Returns deduplicated list of detected tool descriptions.
func scanMapsForInstrumentation(data string) []string {
	var found []string
	for _, line := range strings.Split(data, "\n") {
		lower := strings.ToLower(line)
		for _, s := range suspiciousLibPatterns {
			if strings.Contains(lower, s.pattern) {
				found = append(found, s.tool)
				break
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, f := range found {
		if !seen[f] {
			seen[f] = true
			unique = append(unique, f)
		}
	}
	return unique
}

// checkProcMaps scans /proc/self/maps for suspicious shared libraries
// indicating dynamic instrumentation (Frida, Valgrind) or sanitizers.
func checkProcMaps() debugCheck {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return debugCheck{Name: "Memory Maps (/proc/self/maps)", Status: "ERROR", Details: fmt.Sprintf("Failed to read: %v", err)}
	}
	defer structs.ZeroBytes(data) // opsec: memory maps reveal loaded libraries

	content := string(data)
	found := scanMapsForInstrumentation(content)
	lines := strings.Split(content, "\n")

	if len(found) > 0 {
		return debugCheck{
			Name:    "Memory Maps (/proc/self/maps)",
			Status:  "DETECTED",
			Details: fmt.Sprintf("Suspicious libraries: %s", strings.Join(found, ", ")),
		}
	}
	return debugCheck{Name: "Memory Maps (/proc/self/maps)", Status: "CLEAN", Details: fmt.Sprintf("Scanned %d mappings, no instrumentation libs", len(lines))}
}

// parseProcStatusWarnings parses /proc/self/status content for security indicators.
// Returns a list of warning strings for detected sandbox/container indicators.
func parseProcStatusWarnings(data string) []string {
	var warnings []string
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				switch val {
				case "1":
					warnings = append(warnings, "Seccomp strict mode (sandbox)")
				case "2":
					warnings = append(warnings, "Seccomp filter mode (sandbox/container)")
				}
			}
		}
		if strings.HasPrefix(line, "CapEff:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val == "0000000000000000" {
					warnings = append(warnings, "Zero effective capabilities (restricted/sandboxed)")
				}
			}
		}
	}
	return warnings
}

// checkProcStatus reads additional debug indicators from /proc/self/status:
// - Seccomp mode (may indicate sandbox)
// - CapEff (all-zero effective capabilities suggest container/drop)
func checkProcStatus() debugCheck {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return debugCheck{Name: "Process Status", Status: "ERROR", Details: fmt.Sprintf("Failed to read: %v", err)}
	}
	defer structs.ZeroBytes(data) // opsec

	warnings := parseProcStatusWarnings(string(data))

	if len(warnings) > 0 {
		return debugCheck{
			Name:    "Process Status (/proc/self/status)",
			Status:  "WARNING",
			Details: strings.Join(warnings, "; "),
		}
	}
	return debugCheck{Name: "Process Status (/proc/self/status)", Status: "CLEAN", Details: "Normal capabilities and seccomp state"}
}

// classifyDMIProduct classifies a DMI product name as a VM type.
// Returns the VM type description or empty string if not recognized.
func classifyDMIProduct(productName string) string {
	lower := strings.ToLower(productName)
	if strings.Contains(lower, "virtualbox") {
		return "VirtualBox (DMI)"
	} else if strings.Contains(lower, "vmware") {
		return "VMware (DMI)"
	} else if strings.Contains(lower, "kvm") || strings.Contains(lower, "qemu") {
		return "KVM/QEMU (DMI)"
	} else if strings.Contains(lower, "hyper-v") || strings.Contains(lower, "virtual machine") {
		return "Hyper-V (DMI)"
	} else if strings.Contains(lower, "xen") {
		return "Xen (DMI)"
	}
	return ""
}

// checkSandboxIndicators checks for common VM/sandbox indicators via procfs.
func checkSandboxIndicators() debugCheck {
	var indicators []string

	// Check for hypervisor flag in /proc/cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		content := string(data)
		structs.ZeroBytes(data) // opsec
		if strings.Contains(content, "hypervisor") {
			indicators = append(indicators, "hypervisor CPU flag (VM)")
		}
	}

	// Check DMI product name for VM indicators
	productName := strings.TrimSpace(readFileQuiet("/sys/class/dmi/id/product_name"))
	if vm := classifyDMIProduct(productName); vm != "" {
		indicators = append(indicators, vm)
	}

	// Check for container indicators
	if _, err := os.Stat("/.dockerenv"); err == nil {
		indicators = append(indicators, "Docker container")
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		indicators = append(indicators, "Container runtime")
	}

	if len(indicators) > 0 {
		return debugCheck{
			Name:    "VM/Sandbox Detection",
			Status:  "WARNING",
			Details: strings.Join(indicators, "; "),
		}
	}
	return debugCheck{Name: "VM/Sandbox Detection", Status: "CLEAN", Details: "No VM/sandbox indicators found"}
}

// checkEBPF detects eBPF-based monitoring programs. Modern EDR/detection tools
// (Falco, Tetragon, Tracee, Cilium) use eBPF to hook kernel functions for deep
// process/network/file visibility. eBPF programs are invisible to userspace unless
// actively queried via the bpf() syscall or sysfs.
func checkEBPF() debugCheck {
	var indicators []string

	// Check /sys/fs/bpf/ for pinned BPF programs/maps (used by Cilium, Tetragon, etc.)
	if entries, err := os.ReadDir("/sys/fs/bpf"); err == nil {
		if len(entries) > 0 {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			indicators = append(indicators, fmt.Sprintf("Pinned BPF objects (%d): %s",
				len(names), strings.Join(names, ", ")))
		}
	}

	// Check /proc/*/comm for known eBPF-based monitoring tools
	ebpfTools := map[string]string{
		"falco":             "Falco (eBPF syscall monitoring)",
		"tetragon":          "Tetragon (Cilium runtime enforcement)",
		"tracee":            "Tracee (Aqua eBPF tracing)",
		"bpftrace":          "bpftrace (dynamic tracing)",
		"bpftool":           "bpftool (BPF program inspection)",
		"cilium-agent":      "Cilium (eBPF networking/security)",
		"hubble":            "Hubble (Cilium network observability)",
		"inspektor-gadget":  "Inspektor Gadget (eBPF debugging)",
		"sysdig":            "Sysdig (syscall capture)",
		"pwru":              "pwru (eBPF packet tracer)",
		"bcc-tools":         "BCC (BPF Compiler Collection)",
	}

	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			// Only check numeric PID dirs
			if len(entry.Name()) == 0 || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
				continue
			}
			commData, err := os.ReadFile("/proc/" + entry.Name() + "/comm")
			if err != nil {
				continue
			}
			comm := strings.TrimSpace(string(commData))
			structs.ZeroBytes(commData)
			if tool, ok := ebpfTools[comm]; ok {
				indicators = append(indicators, tool)
			}
		}
	}

	if len(indicators) > 0 {
		return debugCheck{
			Name:    "eBPF Monitoring",
			Status:  "DETECTED",
			Details: strings.Join(indicators, "; "),
		}
	}
	return debugCheck{Name: "eBPF Monitoring", Status: "CLEAN", Details: "No eBPF monitoring programs detected"}
}

// checkAuditd detects the Linux Audit Framework. auditd monitors syscalls and can
// log every file access, process execution, and network connection. Active audit
// rules significantly increase detection risk for red team operations.
func checkAuditd() debugCheck {
	var indicators []string

	// Check if auditd is running by looking for the audit log
	if _, err := os.Stat("/var/log/audit/audit.log"); err == nil {
		indicators = append(indicators, "audit.log exists")
	}

	// Check auditd status via /proc/self/status (audit session ID)
	if data, err := os.ReadFile("/proc/self/loginuid"); err == nil {
		uid := strings.TrimSpace(string(data))
		structs.ZeroBytes(data)
		// 4294967295 (0xFFFFFFFF) means no audit session — process not tracked
		if uid != "4294967295" && uid != "" {
			indicators = append(indicators, fmt.Sprintf("loginuid=%s (audited session)", uid))
		}
	}

	// Check audit rules if readable
	rulesFiles := []string{"/etc/audit/audit.rules", "/etc/audit/rules.d/audit.rules"}
	for _, rf := range rulesFiles {
		data, err := os.ReadFile(rf)
		if err != nil {
			continue
		}
		content := string(data)
		structs.ZeroBytes(data)
		ruleCount := 0
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				ruleCount++
			}
		}
		if ruleCount > 0 {
			indicators = append(indicators, fmt.Sprintf("%s: %d active rules", rf, ruleCount))
		}
	}

	// Check /etc/audit/rules.d/ for additional rule files
	if entries, err := os.ReadDir("/etc/audit/rules.d"); err == nil {
		ruleFiles := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".rules") {
				ruleFiles++
			}
		}
		if ruleFiles > 1 { // >1 because audit.rules is already checked
			indicators = append(indicators, fmt.Sprintf("%d rule files in /etc/audit/rules.d/", ruleFiles))
		}
	}

	if len(indicators) > 0 {
		return debugCheck{
			Name:    "Audit Framework (auditd)",
			Status:  "WARNING",
			Details: strings.Join(indicators, "; "),
		}
	}
	return debugCheck{Name: "Audit Framework (auditd)", Status: "CLEAN", Details: "No auditd indicators found"}
}

// checkPtraceScope reads the kernel ptrace restriction level. This affects the ability
// to attach to processes for injection, credential theft, and anti-debug evasion.
func checkPtraceScope() debugCheck {
	data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return debugCheck{Name: "Ptrace Scope", Status: "CLEAN", Details: "Yama LSM not loaded (ptrace unrestricted)"}
	}
	scope := strings.TrimSpace(string(data))
	structs.ZeroBytes(data)

	var desc string
	var status string
	switch scope {
	case "0":
		desc = "classic — any process can ptrace (full injection capability)"
		status = "CLEAN"
	case "1":
		desc = "restricted — only parent can ptrace (limited injection)"
		status = "WARNING"
	case "2":
		desc = "admin only — ptrace requires CAP_SYS_PTRACE"
		status = "WARNING"
	case "3":
		desc = "disabled — ptrace completely blocked"
		status = "DETECTED"
	default:
		desc = fmt.Sprintf("unknown value: %s", scope)
		status = "WARNING"
	}
	return debugCheck{
		Name:    "Ptrace Scope",
		Status:  status,
		Details: fmt.Sprintf("ptrace_scope=%s (%s)", scope, desc),
	}
}

