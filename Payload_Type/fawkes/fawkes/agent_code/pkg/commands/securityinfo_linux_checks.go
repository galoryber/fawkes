package commands

import (
	"fmt"
	"os"
	"strings"
)

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

	// LD_PRELOAD — library injection detection
	controls = append(controls, checkLDPreload()...)

	// eBPF monitoring — detect runtime security tools using eBPF
	controls = append(controls, checkEBPFMonitoring()...)

	return controls
}

// checkLDPreload detects LD_PRELOAD library injection and /etc/ld.so.preload.
func checkLDPreload() []secControl {
	var controls []secControl

	// Check LD_PRELOAD environment variable
	ldPreload := os.Getenv("LD_PRELOAD")
	if ldPreload != "" {
		controls = append(controls, secControl{"LD_PRELOAD", "warning",
			fmt.Sprintf("active: %s (library injection in effect)", ldPreload)})
	}

	// Check LD_AUDIT (less common but also used for monitoring)
	ldAudit := os.Getenv("LD_AUDIT")
	if ldAudit != "" {
		controls = append(controls, secControl{"LD_AUDIT", "warning",
			fmt.Sprintf("active: %s (runtime link auditing)", ldAudit)})
	}

	// Check /etc/ld.so.preload — system-wide preload (persists across processes)
	preloadFile := readFileQuiet("/etc/ld.so.preload")
	if preloadFile != "" {
		var libs []string
		for _, line := range strings.Split(preloadFile, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				libs = append(libs, line)
			}
		}
		if len(libs) > 0 {
			controls = append(controls, secControl{"ld.so.preload", "warning",
				fmt.Sprintf("%d lib(s): %s", len(libs), strings.Join(libs, ", "))})
		}
	}

	if ldPreload == "" && ldAudit == "" && (preloadFile == "" || !strings.ContainsAny(preloadFile, "/")) {
		controls = append(controls, secControl{"LD_PRELOAD", "not found", "no library injection detected"})
	}

	return controls
}

// checkEBPFMonitoring detects eBPF-based runtime security monitoring tools.
func checkEBPFMonitoring() []secControl {
	var controls []secControl

	// Check for BPF JIT compilation (indicates eBPF is actively used)
	bpfJIT := readFileQuiet("/proc/sys/net/core/bpf_jit_enable")
	if bpfJIT != "" {
		val := strings.TrimSpace(bpfJIT)
		switch val {
		case "0":
			controls = append(controls, secControl{"BPF JIT", "disabled", "eBPF programs interpreted (slower)"})
		case "1":
			controls = append(controls, secControl{"BPF JIT", "enabled", "JIT compilation active"})
		case "2":
			controls = append(controls, secControl{"BPF JIT", "enabled", "JIT always-on (debug mode)"})
		}
	}

	// Check for active kprobes (kernel function hooking — used by monitoring tools)
	kprobes := readFileQuiet("/sys/kernel/debug/tracing/kprobe_events")
	if kprobes != "" {
		lines := 0
		for _, line := range strings.Split(kprobes, "\n") {
			if strings.TrimSpace(line) != "" {
				lines++
			}
		}
		if lines > 0 {
			controls = append(controls, secControl{"kprobe Events", "warning",
				fmt.Sprintf("%d active kprobe(s) — kernel function hooks detected", lines)})
		}
	}

	// Check for active tracepoints
	tracepoints := readFileQuiet("/sys/kernel/debug/tracing/set_event")
	if tracepoints != "" {
		lines := 0
		for _, line := range strings.Split(tracepoints, "\n") {
			if strings.TrimSpace(line) != "" {
				lines++
			}
		}
		if lines > 0 {
			controls = append(controls, secControl{"Tracepoints", "warning",
				fmt.Sprintf("%d active tracepoint(s)", lines)})
		}
	}

	// Detect well-known eBPF security tools by process name
	ebpfTools := map[string]string{
		"tetragon":       "Cilium Tetragon (runtime enforcement)",
		"falco":          "Falco (runtime threat detection)",
		"tracee":         "Aqua Tracee (eBPF security tracing)",
		"bpftrace":       "bpftrace (dynamic tracing active)",
		"sysdig":         "Sysdig (system call monitoring)",
		"cilium-agent":   "Cilium (network + runtime security)",
		"hubble":         "Hubble (Cilium network observability)",
		"pulsar":         "Pulsar (Exein runtime security)",
		"kubearmor":      "KubeArmor (container runtime security)",
		"inspektor-gadget": "Inspektor Gadget (eBPF debugging)",
	}

	procEntries, err := os.ReadDir("/proc")
	if err == nil {
		seen := make(map[string]bool)
		for _, entry := range procEntries {
			if !entry.IsDir() {
				continue
			}
			// Only check numeric PID dirs
			name := entry.Name()
			if len(name) == 0 || name[0] < '0' || name[0] > '9' {
				continue
			}
			comm := strings.TrimSpace(readFileQuiet(fmt.Sprintf("/proc/%s/comm", name)))
			if comm == "" {
				continue
			}
			if desc, ok := ebpfTools[comm]; ok && !seen[comm] {
				seen[comm] = true
				controls = append(controls, secControl{"eBPF Monitor", "warning",
					fmt.Sprintf("%s — PID %s", desc, name)})
			}
		}
	}

	// If no eBPF monitoring tools detected, report clean
	hasWarning := false
	for _, c := range controls {
		if c.Status == "warning" && (strings.Contains(c.Name, "kprobe") ||
			strings.Contains(c.Name, "Tracepoint") ||
			strings.Contains(c.Name, "eBPF")) {
			hasWarning = true
			break
		}
	}
	if !hasWarning {
		controls = append(controls, secControl{"eBPF Monitoring", "not found", "no runtime security tools detected"})
	}

	return controls
}
