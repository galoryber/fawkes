package commands

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// SecurityInfoCommand reports security posture and controls.
type SecurityInfoCommand struct{}

func (c *SecurityInfoCommand) Name() string        { return "security-info" }
func (c *SecurityInfoCommand) Description() string { return "Report security posture and active controls" }

type secControl struct {
	Name    string
	Status  string // "enabled", "disabled", "not found", "info", "warning"
	Details string
}

func (c *SecurityInfoCommand) Execute(task structs.Task) structs.CommandResult {
	var controls []secControl

	switch runtime.GOOS {
	case "linux":
		controls = securityInfoLinux()
	case "darwin":
		controls = securityInfoDarwin()
	case "windows":
		controls = securityInfoWindows()
	}

	var sb strings.Builder
	sb.WriteString("[*] Security Posture Report\n\n")
	sb.WriteString(fmt.Sprintf("%-30s %-12s %s\n", "Control", "Status", "Details"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	enabledCount := 0
	for _, ctl := range controls {
		indicator := "  "
		switch ctl.Status {
		case "enabled":
			indicator = "[+]"
			enabledCount++
		case "disabled":
			indicator = "[-]"
		case "warning":
			indicator = "[!]"
		default:
			indicator = "[?]"
		}
		sb.WriteString(fmt.Sprintf("%s %-27s %-12s %s\n", indicator, ctl.Name, ctl.Status, ctl.Details))
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d/%d security controls active\n", enabledCount, len(controls)))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func securityInfoLinux() []secControl {
	var controls []secControl

	// SELinux
	getenforce := runQuietCommand("getenforce")
	if getenforce != "" {
		mode := strings.TrimSpace(getenforce)
		if strings.EqualFold(mode, "enforcing") {
			controls = append(controls, secControl{"SELinux", "enabled", "Enforcing mode"})
		} else if strings.EqualFold(mode, "permissive") {
			controls = append(controls, secControl{"SELinux", "warning", "Permissive mode (logging only)"})
		} else {
			controls = append(controls, secControl{"SELinux", "disabled", mode})
		}
	} else {
		controls = append(controls, secControl{"SELinux", "not found", "getenforce not available"})
	}

	// AppArmor
	aaStatus := runQuietCommand("aa-status", "--json")
	if aaStatus != "" {
		controls = append(controls, secControl{"AppArmor", "enabled", "aa-status available"})
	} else {
		aaEnabled := runQuietCommand("cat", "/sys/module/apparmor/parameters/enabled")
		if strings.TrimSpace(aaEnabled) == "Y" {
			controls = append(controls, secControl{"AppArmor", "enabled", "kernel module loaded"})
		} else {
			controls = append(controls, secControl{"AppArmor", "not found", ""})
		}
	}

	// Seccomp
	seccomp := readFileQuiet("/proc/self/status")
	if seccomp != "" {
		for _, line := range strings.Split(seccomp, "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				val := strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
				switch val {
				case "0":
					controls = append(controls, secControl{"Seccomp", "disabled", "not filtered"})
				case "1":
					controls = append(controls, secControl{"Seccomp", "enabled", "strict mode"})
				case "2":
					controls = append(controls, secControl{"Seccomp", "enabled", "filter mode (BPF)"})
				}
				break
			}
		}
	}

	// Audit daemon
	auditStatus := runQuietCommand("auditctl", "-s")
	if strings.Contains(auditStatus, "enabled") {
		controls = append(controls, secControl{"Linux Audit (auditd)", "enabled", ""})
	} else if auditStatus != "" {
		controls = append(controls, secControl{"Linux Audit (auditd)", "info", strings.TrimSpace(auditStatus)})
	} else {
		controls = append(controls, secControl{"Linux Audit (auditd)", "not found", ""})
	}

	// Firewall (iptables)
	iptables := runQuietCommand("iptables", "-L", "-n", "--line-numbers")
	if iptables != "" {
		lines := strings.Split(strings.TrimSpace(iptables), "\n")
		ruleCount := 0
		for _, line := range lines {
			if !strings.HasPrefix(line, "Chain") && !strings.HasPrefix(line, "num") && strings.TrimSpace(line) != "" {
				ruleCount++
			}
		}
		if ruleCount > 0 {
			controls = append(controls, secControl{"iptables", "enabled", fmt.Sprintf("%d rules", ruleCount)})
		} else {
			controls = append(controls, secControl{"iptables", "disabled", "no rules"})
		}
	}

	// nftables
	nft := runQuietCommand("nft", "list", "ruleset")
	if nft != "" && len(strings.TrimSpace(nft)) > 10 {
		controls = append(controls, secControl{"nftables", "enabled", "ruleset present"})
	}

	// ASLR
	aslr := readFileQuiet("/proc/sys/kernel/randomize_va_space")
	if aslr != "" {
		val := strings.TrimSpace(aslr)
		switch val {
		case "0":
			controls = append(controls, secControl{"ASLR", "disabled", ""})
		case "1":
			controls = append(controls, secControl{"ASLR", "enabled", "partial (shared libs only)"})
		case "2":
			controls = append(controls, secControl{"ASLR", "enabled", "full (stack, heap, mmap)"})
		}
	}

	// Kernel lockdown
	lockdown := readFileQuiet("/sys/kernel/security/lockdown")
	if lockdown != "" {
		controls = append(controls, secControl{"Kernel Lockdown", "info", strings.TrimSpace(lockdown)})
	}

	// YAMA ptrace scope
	yama := readFileQuiet("/proc/sys/kernel/yama/ptrace_scope")
	if yama != "" {
		val := strings.TrimSpace(yama)
		switch val {
		case "0":
			controls = append(controls, secControl{"YAMA ptrace", "disabled", "any process can trace"})
		case "1":
			controls = append(controls, secControl{"YAMA ptrace", "enabled", "parent-only tracing"})
		case "2":
			controls = append(controls, secControl{"YAMA ptrace", "enabled", "admin-only tracing"})
		case "3":
			controls = append(controls, secControl{"YAMA ptrace", "enabled", "no tracing allowed"})
		}
	}

	return controls
}

func securityInfoDarwin() []secControl {
	var controls []secControl

	// System Integrity Protection (SIP)
	csrutil := runQuietCommand("csrutil", "status")
	if strings.Contains(csrutil, "enabled") {
		controls = append(controls, secControl{"SIP (csrutil)", "enabled", ""})
	} else if strings.Contains(csrutil, "disabled") {
		controls = append(controls, secControl{"SIP (csrutil)", "disabled", ""})
	} else {
		controls = append(controls, secControl{"SIP (csrutil)", "info", strings.TrimSpace(csrutil)})
	}

	// Gatekeeper
	spctl := runQuietCommand("spctl", "--status")
	if strings.Contains(spctl, "enabled") {
		controls = append(controls, secControl{"Gatekeeper", "enabled", ""})
	} else if strings.Contains(spctl, "disabled") {
		controls = append(controls, secControl{"Gatekeeper", "disabled", ""})
	}

	// FileVault
	fdesetup := runQuietCommand("fdesetup", "status")
	if strings.Contains(fdesetup, "On") {
		controls = append(controls, secControl{"FileVault", "enabled", "full disk encryption"})
	} else if strings.Contains(fdesetup, "Off") {
		controls = append(controls, secControl{"FileVault", "disabled", ""})
	}

	// Firewall
	fwCheck := runQuietCommand("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate")
	if strings.TrimSpace(fwCheck) != "0" && fwCheck != "" {
		controls = append(controls, secControl{"macOS Firewall", "enabled", "globalstate=" + strings.TrimSpace(fwCheck)})
	} else {
		controls = append(controls, secControl{"macOS Firewall", "disabled", ""})
	}

	// XProtect
	xprotect := runQuietCommand("system_profiler", "SPInstallHistoryDataType")
	if strings.Contains(xprotect, "XProtect") {
		controls = append(controls, secControl{"XProtect", "enabled", "malware definitions present"})
	}

	return controls
}

func securityInfoWindows() []secControl {
	var controls []secControl

	// Windows Defender status
	defenderCmd := `(Get-MpComputerStatus).RealTimeProtectionEnabled`
	defender := runQuietCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", defenderCmd)
	if strings.Contains(strings.TrimSpace(defender), "True") {
		controls = append(controls, secControl{"Windows Defender RT", "enabled", "real-time protection"})
	} else if strings.Contains(strings.TrimSpace(defender), "False") {
		controls = append(controls, secControl{"Windows Defender RT", "disabled", ""})
	}

	// AMSI
	controls = append(controls, secControl{"AMSI", "enabled", "default on Windows 10+"})

	// Credential Guard
	credGuardCmd := `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning`
	credGuard := runQuietCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", credGuardCmd)
	if strings.Contains(credGuard, "1") || strings.Contains(credGuard, "2") {
		controls = append(controls, secControl{"Credential Guard", "enabled", ""})
	} else {
		controls = append(controls, secControl{"Credential Guard", "disabled", ""})
	}

	// UAC level
	uacCmd := `(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA`
	uac := runQuietCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", uacCmd)
	if strings.TrimSpace(uac) == "1" {
		controls = append(controls, secControl{"UAC", "enabled", ""})
	} else {
		controls = append(controls, secControl{"UAC", "disabled", ""})
	}

	// Windows Firewall
	fwCmd := `Get-NetFirewallProfile | ForEach-Object { "$($_.Name):$($_.Enabled)" }`
	fw := runQuietCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", fwCmd)
	if fw != "" {
		profiles := strings.TrimSpace(fw)
		controls = append(controls, secControl{"Windows Firewall", "info", profiles})
	}

	// BitLocker
	blCmd := `(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus`
	bl := runQuietCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", blCmd)
	if strings.TrimSpace(bl) == "On" {
		controls = append(controls, secControl{"BitLocker (C:)", "enabled", "volume encrypted"})
	} else if strings.TrimSpace(bl) == "Off" {
		controls = append(controls, secControl{"BitLocker (C:)", "disabled", ""})
	}

	// PowerShell Constrained Language Mode
	clmCmd := `$ExecutionContext.SessionState.LanguageMode`
	clm := runQuietCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", clmCmd)
	if strings.Contains(clm, "ConstrainedLanguage") {
		controls = append(controls, secControl{"PS Constrained Lang", "enabled", "CLM active"})
	} else if strings.Contains(clm, "FullLanguage") {
		controls = append(controls, secControl{"PS Constrained Lang", "disabled", "FullLanguage mode"})
	}

	return controls
}

// readFileQuiet reads a file and returns content, or empty string on error.
func readFileQuiet(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
