//go:build darwin

package commands

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// runPlatformDebugChecks runs macOS-specific anti-debug checks.
func runPlatformDebugChecks() []debugCheck {
	var checks []debugCheck

	checks = append(checks, checkSysctlPTraced())
	checks = append(checks, checkDyldInsertLibraries())
	checks = append(checks, checkVMIndicators())
	checks = append(checks, checkSecurityProducts())
	checks = append(checks, checkAnalysisEnvironment())

	return checks
}

// checkSysctlPTraced uses sysctl to check the P_TRACED flag on the current process.
func checkSysctlPTraced() debugCheck {
	// struct kinfo_proc lookup via sysctl
	const (
		ctlKern     = 1
		kernProc    = 14
		kernProcPID = 1
	)

	pid := os.Getpid()
	mib := [4]int32{ctlKern, kernProc, kernProcPID, int32(pid)}

	// First call to get size
	var size uintptr
	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)
	if errno != 0 {
		return debugCheck{Name: "sysctl P_TRACED", Status: "ERROR", Details: fmt.Sprintf("sysctl size query failed: %v", errno)}
	}

	// Allocate buffer and get data
	buf := make([]byte, size)
	_, _, errno = syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)
	if errno != 0 {
		return debugCheck{Name: "sysctl P_TRACED", Status: "ERROR", Details: fmt.Sprintf("sysctl query failed: %v", errno)}
	}

	// kp_proc.p_flag is at offset 32 in struct kinfo_proc on arm64/amd64 macOS
	// P_TRACED = 0x00000800
	const (
		kpProcPFlagOffset = 32
		pTraced           = 0x00000800
	)

	if len(buf) > kpProcPFlagOffset+4 {
		flags := *(*int32)(unsafe.Pointer(&buf[kpProcPFlagOffset]))
		if flags&pTraced != 0 {
			return debugCheck{Name: "sysctl P_TRACED", Status: "DETECTED", Details: "Process is being traced (debugger attached)"}
		}
		return debugCheck{Name: "sysctl P_TRACED", Status: "CLEAN", Details: "Not traced"}
	}

	return debugCheck{Name: "sysctl P_TRACED", Status: "ERROR", Details: "Buffer too small for kinfo_proc"}
}

// checkDyldInsertLibraries checks for DYLD_INSERT_LIBRARIES which may indicate library injection.
func checkDyldInsertLibraries() debugCheck {
	val := os.Getenv("DYLD_INSERT_LIBRARIES")
	if val != "" {
		return debugCheck{
			Name:    "DYLD_INSERT_LIBRARIES",
			Status:  "WARNING",
			Details: fmt.Sprintf("Set: %s", val),
		}
	}
	return debugCheck{Name: "DYLD_INSERT_LIBRARIES", Status: "CLEAN", Details: "Not set"}
}

// checkVMIndicators detects virtual machine environments via sysctl queries.
// Uses native sysctl — no child process spawned.
func checkVMIndicators() debugCheck {
	var indicators []string

	// kern.hv_vmm_present is 1 when running under a hypervisor (Hypervisor.framework)
	if val, err := unix.SysctlUint32("kern.hv_vmm_present"); err == nil && val == 1 {
		indicators = append(indicators, "hypervisor present (kern.hv_vmm_present=1)")
	}

	// hw.model identifies the hardware — VMs have distinctive models
	if model, err := unix.Sysctl("hw.model"); err == nil {
		indicators = append(indicators, classifyDarwinHWModel(model)...)
	}

	// machdep.cpu.brand_string may contain VM-specific CPU branding
	if brand, err := unix.Sysctl("machdep.cpu.brand_string"); err == nil {
		lower := strings.ToLower(brand)
		if strings.Contains(lower, "qemu") {
			indicators = append(indicators, "QEMU CPU brand")
		}
	}

	// Check for VM-specific kernel extensions
	if kextList, err := unix.Sysctl("hw.optional.arm64"); err == nil {
		_ = kextList // just probing — arm64 on x86 VM indicates Rosetta/UTM
	}

	if len(indicators) > 0 {
		return debugCheck{
			Name:    "VM Detection (sysctl)",
			Status:  "WARNING",
			Details: strings.Join(indicators, "; "),
		}
	}
	return debugCheck{Name: "VM Detection (sysctl)", Status: "CLEAN", Details: "No VM indicators found"}
}

// classifyDarwinHWModel checks hw.model for known VM identifiers.
func classifyDarwinHWModel(model string) []string {
	var indicators []string
	lower := strings.ToLower(model)

	vmModels := []struct {
		pattern string
		name    string
	}{
		{"vmware", "VMware"},
		{"virtualbox", "VirtualBox"},
		{"parallels", "Parallels Desktop"},
		{"qemu", "QEMU"},
		{"utm", "UTM"},
		{"virtual", "Virtual Machine"},
	}

	for _, vm := range vmModels {
		if strings.Contains(lower, vm.pattern) {
			indicators = append(indicators, fmt.Sprintf("%s (hw.model=%s)", vm.name, model))
			break
		}
	}

	return indicators
}

// macOSSecurityProducts maps LaunchDaemon/Agent plist names to security product names.
var macOSSecurityProducts = []struct {
	path    string
	product string
}{
	// EDR / endpoint protection
	{"/Library/LaunchDaemons/com.crowdstrike.falcond.plist", "CrowdStrike Falcon"},
	{"/Library/LaunchDaemons/com.sentinelone.sentineld.plist", "SentinelOne"},
	{"/Library/LaunchDaemons/com.microsoft.wdav.daemon.plist", "Microsoft Defender"},
	{"/Library/LaunchDaemons/com.carbonblack.daemon.plist", "VMware Carbon Black"},
	{"/Library/LaunchDaemons/com.tanium.taniumclient.plist", "Tanium"},
	{"/Library/LaunchDaemons/com.cybereason.sensor.plist", "Cybereason"},
	{"/Library/LaunchDaemons/com.paloaltonetworks.cortex.xdr.plist", "Cortex XDR"},
	{"/Library/LaunchDaemons/com.elastic.endpoint.plist", "Elastic Endpoint"},
	// Antivirus
	{"/Library/LaunchDaemons/com.eset.remoteadministrator.agent.plist", "ESET"},
	{"/Library/LaunchDaemons/com.sophos.endpoint.scanextension.plist", "Sophos"},
	{"/Library/LaunchDaemons/com.kaspersky.avscan.plist", "Kaspersky"},
	{"/Library/LaunchDaemons/com.malwarebytes.mbam.rtprotection.daemon.plist", "Malwarebytes"},
	// MDM / device management
	{"/Library/LaunchDaemons/com.jamfsoftware.jamf.daemon.plist", "JAMF"},
	{"/Library/LaunchDaemons/com.mosyle.agent.plist", "Mosyle"},
	{"/Library/LaunchDaemons/com.kandji.profile.mdmclient.daemon.plist", "Kandji"},
	// Monitoring / logging
	{"/Library/LaunchDaemons/com.osquery.osqueryd.plist", "osquery"},
	{"/Library/LaunchDaemons/com.google.santa.daemon.plist", "Santa (Google)"},
	{"/Library/LaunchDaemons/org.macports.syslog-ng.plist", "syslog-ng"},
}

// checkSecurityProducts detects installed EDR/AV/monitoring products
// by checking for their LaunchDaemon plists — no child process spawned.
func checkSecurityProducts() debugCheck {
	var found []string

	for _, sp := range macOSSecurityProducts {
		if _, err := os.Stat(sp.path); err == nil {
			found = append(found, sp.product)
		}
	}

	// Also check for Endpoint Security system extensions
	esExtDir := "/Library/SystemExtensions"
	if entries, err := os.ReadDir(esExtDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				name := strings.ToLower(entry.Name())
				if strings.Contains(name, "crowdstrike") || strings.Contains(name, "sentinel") ||
					strings.Contains(name, "microsoft") || strings.Contains(name, "carbonblack") ||
					strings.Contains(name, "cortex") || strings.Contains(name, "elastic") {
					found = append(found, fmt.Sprintf("SystemExtension: %s", entry.Name()))
				}
			}
		}
	}

	if len(found) > 0 {
		return debugCheck{
			Name:    "Security Products (LaunchDaemons)",
			Status:  "WARNING",
			Details: fmt.Sprintf("%d found: %s", len(found), strings.Join(found, ", ")),
		}
	}
	return debugCheck{Name: "Security Products (LaunchDaemons)", Status: "CLEAN", Details: "No known security products detected"}
}

// checkAnalysisEnvironment detects App Sandbox and analysis-related
// environment variables that indicate debugging or memory analysis.
func checkAnalysisEnvironment() debugCheck {
	var warnings []string

	// APP_SANDBOX_CONTAINER_ID is set when running inside App Sandbox
	if val := os.Getenv("APP_SANDBOX_CONTAINER_ID"); val != "" {
		warnings = append(warnings, fmt.Sprintf("App Sandbox active (container: %s)", val))
	}

	// HOME inside sandbox is ~/Library/Containers/<bundle-id>/Data
	home := os.Getenv("HOME")
	if strings.Contains(home, "/Library/Containers/") {
		warnings = append(warnings, fmt.Sprintf("Sandboxed HOME: %s", home))
	}

	// Check for analysis-related environment variables
	analysisVars := []struct {
		env  string
		desc string
	}{
		{"MallocStackLogging", "Malloc stack logging (memory analysis)"},
		{"MallocStackLoggingNoCompact", "Malloc stack logging (no compact)"},
		{"NSZombieEnabled", "NSZombie enabled (memory debugging)"},
		{"MallocGuardEdges", "Malloc guard edges (memory analysis)"},
		{"MallocScribble", "Malloc scribble (memory analysis)"},
		{"DYLD_PRINT_LIBRARIES", "DYLD library load tracing"},
		{"DYLD_PRINT_APIS", "DYLD API tracing"},
	}

	for _, av := range analysisVars {
		if val := os.Getenv(av.env); val != "" {
			warnings = append(warnings, av.desc)
		}
	}

	if len(warnings) > 0 {
		return debugCheck{
			Name:    "Sandbox/Analysis Environment",
			Status:  "WARNING",
			Details: strings.Join(warnings, "; "),
		}
	}
	return debugCheck{Name: "Sandbox/Analysis Environment", Status: "CLEAN", Details: "No sandbox or analysis indicators"}
}
