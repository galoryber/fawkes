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

func (c *SecurityInfoCommand) Name() string { return "security-info" }
func (c *SecurityInfoCommand) Description() string {
	return "Report security posture and active controls"
}

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
		var indicator string
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

	return successResult(sb.String())
}

func securityInfoLinux() []secControl {
	var controls []secControl

	// SELinux — read from sysfs first (no subprocess), fall back to getenforce
	selinuxEnforce := readFileQuiet("/sys/fs/selinux/enforce")
	if selinuxEnforce != "" {
		val := strings.TrimSpace(selinuxEnforce)
		if val == "1" {
			controls = append(controls, secControl{"SELinux", "enabled", "Enforcing mode"})
		} else {
			controls = append(controls, secControl{"SELinux", "warning", "Permissive mode (logging only)"})
		}
	} else if getenforce := runQuietCommand("getenforce"); getenforce != "" {
		mode := strings.TrimSpace(getenforce)
		if strings.EqualFold(mode, "enforcing") {
			controls = append(controls, secControl{"SELinux", "enabled", "Enforcing mode"})
		} else if strings.EqualFold(mode, "permissive") {
			controls = append(controls, secControl{"SELinux", "warning", "Permissive mode (logging only)"})
		} else {
			controls = append(controls, secControl{"SELinux", "disabled", mode})
		}
	} else {
		controls = append(controls, secControl{"SELinux", "not found", "not available"})
	}

	// AppArmor — check kernel module first (no subprocess), fall back to aa-status
	aaEnabled := readFileQuiet("/sys/module/apparmor/parameters/enabled")
	if strings.TrimSpace(aaEnabled) == "Y" {
		controls = append(controls, secControl{"AppArmor", "enabled", "kernel module loaded"})
	} else if aaStatus := runQuietCommand("aa-status", "--json"); aaStatus != "" {
		controls = append(controls, secControl{"AppArmor", "enabled", "aa-status available"})
	} else {
		controls = append(controls, secControl{"AppArmor", "not found", ""})
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

	// Audit daemon — native detection via procfs/pidfile (no subprocess)
	auditDetected := false
	// Check loginuid: a valid UID (not 4294967295) means audit tracking is active
	loginuid := readFileQuiet("/proc/self/loginuid")
	if loginuid != "" {
		val := strings.TrimSpace(loginuid)
		if val != "4294967295" && val != "" {
			auditDetected = true
		}
	}
	// Check if auditd PID file exists (standard location)
	auditPid := readFileQuiet("/var/run/auditd.pid")
	if auditPid == "" {
		auditPid = readFileQuiet("/run/auditd.pid")
	}
	if auditPid != "" {
		auditDetected = true
	}
	if auditDetected {
		details := "kernel audit active"
		if auditPid != "" {
			details += ", auditd running (pid " + strings.TrimSpace(auditPid) + ")"
		}
		controls = append(controls, secControl{"Linux Audit (auditd)", "enabled", details})
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

	// Active LSMs (Landlock, BPF LSM, TOMOYO, etc.)
	lsm := readFileQuiet("/sys/kernel/security/lsm")
	if lsm != "" {
		modules := strings.TrimSpace(lsm)
		controls = append(controls, secControl{"LSM Stack", "info", modules})
		if strings.Contains(modules, "landlock") {
			controls = append(controls, secControl{"Landlock", "enabled", "sandboxing LSM"})
		}
		if strings.Contains(modules, "bpf") {
			controls = append(controls, secControl{"BPF LSM", "enabled", "eBPF security hooks"})
		}
		if strings.Contains(modules, "tomoyo") {
			controls = append(controls, secControl{"TOMOYO", "enabled", "pathname-based MAC"})
		}
	}

	// Unprivileged BPF restriction
	bpfRestrict := readFileQuiet("/proc/sys/kernel/unprivileged_bpf_disabled")
	if bpfRestrict != "" {
		val := strings.TrimSpace(bpfRestrict)
		switch val {
		case "0":
			controls = append(controls, secControl{"Unprivileged BPF", "disabled", "any user can load BPF programs"})
		case "1":
			controls = append(controls, secControl{"Unprivileged BPF", "enabled", "restricted to CAP_BPF"})
		case "2":
			controls = append(controls, secControl{"Unprivileged BPF", "enabled", "permanently restricted"})
		}
	}

	// kptr_restrict — hides kernel pointers from non-root
	kptr := readFileQuiet("/proc/sys/kernel/kptr_restrict")
	if kptr != "" {
		val := strings.TrimSpace(kptr)
		switch val {
		case "0":
			controls = append(controls, secControl{"kptr_restrict", "disabled", "kernel pointers visible"})
		case "1":
			controls = append(controls, secControl{"kptr_restrict", "enabled", "hidden from non-CAP_SYSLOG"})
		case "2":
			controls = append(controls, secControl{"kptr_restrict", "enabled", "hidden from all users"})
		}
	}

	// dmesg_restrict — limits dmesg to root
	dmesg := readFileQuiet("/proc/sys/kernel/dmesg_restrict")
	if dmesg != "" {
		if strings.TrimSpace(dmesg) == "1" {
			controls = append(controls, secControl{"dmesg_restrict", "enabled", "kernel logs require CAP_SYSLOG"})
		} else {
			controls = append(controls, secControl{"dmesg_restrict", "disabled", "kernel logs readable by all"})
		}
	}

	// Disk encryption — check for dm-crypt/LUKS devices
	if dmEntries, err := os.ReadDir("/dev/mapper"); err == nil {
		var encrypted []string
		for _, e := range dmEntries {
			name := e.Name()
			if name != "control" && !strings.HasPrefix(name, ".") {
				encrypted = append(encrypted, name)
			}
		}
		if len(encrypted) > 0 {
			controls = append(controls, secControl{"dm-crypt/LUKS", "enabled",
				fmt.Sprintf("%d device(s): %s", len(encrypted), strings.Join(encrypted, ", "))})
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
	// Try native registry reading first (no subprocess spawned for Defender/UAC/Firewall/CredGuard)
	controls := securityInfoWindowsNative()

	// Fall back to PowerShell if native reading failed entirely
	if controls == nil {
		defenderCmd := `(Get-MpComputerStatus).RealTimeProtectionEnabled`
		defender := runQuietCommand("powershell", BuildPSArgs(defenderCmd, InternalPSOptions())...)
		if strings.Contains(strings.TrimSpace(defender), "True") {
			controls = append(controls, secControl{"Windows Defender RT", "enabled", "real-time protection"})
		} else if strings.Contains(strings.TrimSpace(defender), "False") {
			controls = append(controls, secControl{"Windows Defender RT", "disabled", ""})
		}

		controls = append(controls, secControl{"AMSI", "enabled", "default on Windows 10+"})

		credGuardCmd := `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning`
		credGuard := runQuietCommand("powershell", BuildPSArgs(credGuardCmd, InternalPSOptions())...)
		if strings.Contains(credGuard, "1") || strings.Contains(credGuard, "2") {
			controls = append(controls, secControl{"Credential Guard", "enabled", ""})
		} else {
			controls = append(controls, secControl{"Credential Guard", "disabled", ""})
		}

		uacCmd := `(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA`
		uac := runQuietCommand("powershell", BuildPSArgs(uacCmd, InternalPSOptions())...)
		if strings.TrimSpace(uac) == "1" {
			controls = append(controls, secControl{"UAC", "enabled", ""})
		} else {
			controls = append(controls, secControl{"UAC", "disabled", ""})
		}

		fwCmd := `Get-NetFirewallProfile | ForEach-Object { "$($_.Name):$($_.Enabled)" }`
		fw := runQuietCommand("powershell", BuildPSArgs(fwCmd, InternalPSOptions())...)
		if fw != "" {
			controls = append(controls, secControl{"Windows Firewall", "info", strings.TrimSpace(fw)})
		}
	}

	// BitLocker and PS CLM always require PowerShell (no registry equivalent)
	blCmd := `(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus`
	bl := runQuietCommand("powershell", BuildPSArgs(blCmd, InternalPSOptions())...)
	if strings.TrimSpace(bl) == "On" {
		controls = append(controls, secControl{"BitLocker (C:)", "enabled", "volume encrypted"})
	} else if strings.TrimSpace(bl) == "Off" {
		controls = append(controls, secControl{"BitLocker (C:)", "disabled", ""})
	}

	clmCmd := `$ExecutionContext.SessionState.LanguageMode`
	clm := runQuietCommand("powershell", BuildPSArgs(clmCmd, InternalPSOptions())...)
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
