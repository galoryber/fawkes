//go:build linux

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// privescCheckModprobe checks for writable modprobe configuration files and
// kernel module loading hooks that could be abused for privilege escalation.
// install directives in modprobe.d run arbitrary commands when a module is loaded.
func privescCheckModprobe() structs.CommandResult {
	var sb strings.Builder

	// Check modprobe.d directories for writable configs and install hooks
	modprobeDirs := []string{"/etc/modprobe.d", "/lib/modprobe.d", "/usr/lib/modprobe.d", "/run/modprobe.d"}
	var installHooks []string
	var writableConfigs []string

	for _, dir := range modprobeDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())

			if isWritableFile(path) {
				writableConfigs = append(writableConfigs, fmt.Sprintf("  [!] WRITABLE: %s", path))
			}

			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := string(data)
			structs.ZeroBytes(data)

			// Look for install/remove directives that run commands
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.HasPrefix(line, "install ") || strings.HasPrefix(line, "remove ") {
					installHooks = append(installHooks, fmt.Sprintf("  %s: %s", path, line))
				}
			}
		}
	}

	// Check modprobe.d directory writability
	for _, dir := range modprobeDirs {
		if isDirWritable(dir) {
			sb.WriteString(fmt.Sprintf("[!!] CRITICAL: %s is WRITABLE — drop config to run commands on module load\n", dir))
		}
	}

	if len(writableConfigs) > 0 {
		sb.WriteString(fmt.Sprintf("\nWritable modprobe configs (%d):\n", len(writableConfigs)))
		sb.WriteString(strings.Join(writableConfigs, "\n"))
		sb.WriteString("\n")
	}

	if len(installHooks) > 0 {
		sb.WriteString(fmt.Sprintf("\nInstall/remove hooks (%d) — commands run on module load/unload:\n", len(installHooks)))
		sb.WriteString(strings.Join(installHooks, "\n"))
		sb.WriteString("\n")
	}

	// Check /etc/modules and /etc/modules-load.d/ for writable module lists
	modulesFiles := []string{"/etc/modules"}
	if entries, err := os.ReadDir("/etc/modules-load.d"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				modulesFiles = append(modulesFiles, filepath.Join("/etc/modules-load.d", entry.Name()))
			}
		}
	}

	var writableModules []string
	for _, path := range modulesFiles {
		if isWritableFile(path) {
			writableModules = append(writableModules,
				fmt.Sprintf("  [!] WRITABLE: %s — can add modules to auto-load", path))
		}
	}

	if len(writableModules) > 0 {
		sb.WriteString(fmt.Sprintf("\nWritable module lists (%d):\n", len(writableModules)))
		sb.WriteString(strings.Join(writableModules, "\n"))
		sb.WriteString("\n")
	}

	// Check if modprobe binary itself has unusual permissions
	modprobePaths := []string{"/usr/sbin/modprobe", "/sbin/modprobe"}
	for _, mp := range modprobePaths {
		info, err := os.Stat(mp)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSetuid != 0 {
			sb.WriteString(fmt.Sprintf("\n[!] %s is SUID — unusual, potential escalation\n", mp))
		}
		break
	}

	if len(installHooks) == 0 && len(writableConfigs) == 0 && len(writableModules) == 0 {
		sb.WriteString("No writable modprobe configs or install hooks found — modprobe is not an escalation vector")
	}

	return successResult(sb.String())
}

// privescCheckLdPreload checks for ld.so.preload abuse vectors.
// /etc/ld.so.preload causes the dynamic linker to load specified libraries into every process,
// making it a powerful persistence and privilege escalation mechanism.
func privescCheckLdPreload() structs.CommandResult {
	var sb strings.Builder
	var findings int

	// Check /etc/ld.so.preload
	preloadPath := "/etc/ld.so.preload"
	if data, err := os.ReadFile(preloadPath); err == nil {
		content := strings.TrimSpace(string(data))
		structs.ZeroBytes(data)

		if content != "" {
			sb.WriteString("[!] /etc/ld.so.preload EXISTS with content:\n")
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				sb.WriteString(fmt.Sprintf("  → %s", line))
				// Check if the preloaded library is writable
				if isWritableFile(line) {
					sb.WriteString(" [WRITABLE — can inject code into ALL processes]")
					findings++
				}
				// Check if the library exists
				if _, err := os.Stat(line); os.IsNotExist(err) {
					sb.WriteString(" [MISSING — create this file to inject code]")
					findings++
				}
				sb.WriteString("\n")
			}
		} else {
			sb.WriteString("/etc/ld.so.preload exists but is empty\n")
		}

		// Check if ld.so.preload itself is writable
		if isWritableFile(preloadPath) {
			sb.WriteString("[!!] CRITICAL: /etc/ld.so.preload is WRITABLE — add library path to inject into all processes\n")
			findings++
		}
	} else {
		// File doesn't exist — check if we can create it
		if isDirWritable("/etc") {
			sb.WriteString("[!!] CRITICAL: /etc is writable — can create /etc/ld.so.preload for global library injection\n")
			findings++
		} else {
			sb.WriteString("/etc/ld.so.preload does not exist (normal)\n")
		}
	}

	// Check LD_PRELOAD environment variable
	if val := os.Getenv("LD_PRELOAD"); val != "" {
		sb.WriteString(fmt.Sprintf("[!] LD_PRELOAD is set: %s\n", val))
		sb.WriteString("  → Libraries are injected into this process's children\n")
		findings++
	}

	// Check LD_LIBRARY_PATH for writable directories
	if val := os.Getenv("LD_LIBRARY_PATH"); val != "" {
		var writableDirs []string
		for _, dir := range strings.Split(val, ":") {
			if dir != "" && isDirWritable(dir) {
				writableDirs = append(writableDirs, dir)
			}
		}
		if len(writableDirs) > 0 {
			sb.WriteString(fmt.Sprintf("[!] LD_LIBRARY_PATH has %d writable directories:\n", len(writableDirs)))
			for _, d := range writableDirs {
				sb.WriteString(fmt.Sprintf("  → %s — place malicious .so to hijack library loading\n", d))
			}
			findings++
		}
	}

	// Check /etc/ld.so.conf.d/ for writable configs
	ldConfDirs := []string{"/etc/ld.so.conf.d"}
	for _, dir := range ldConfDirs {
		if isDirWritable(dir) {
			sb.WriteString(fmt.Sprintf("[!] %s is writable — can add library search paths\n", dir))
			findings++
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if isWritableFile(path) {
				sb.WriteString(fmt.Sprintf("  [!] Writable ld config: %s\n", path))
				findings++
			}
		}
	}

	if findings == 0 {
		sb.WriteString("No ld.so.preload or library path escalation vectors found")
	}

	return successResult(sb.String())
}

// privescCheckSecurityModules checks the status of Linux security modules
// (AppArmor, SELinux). Disabled or permissive security modules indicate
// reduced system hardening — potential for unmonitored privilege escalation.
func privescCheckSecurityModules() structs.CommandResult {
	var sb strings.Builder

	// --- AppArmor ---
	sb.WriteString("AppArmor:\n")
	appArmorFound := false

	// Check if AppArmor kernel module is loaded
	if _, err := os.Stat("/sys/module/apparmor"); err == nil {
		appArmorFound = true
		// Read status
		if data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
			enabled := strings.TrimSpace(string(data))
			structs.ZeroBytes(data)
			if enabled == "Y" {
				sb.WriteString("  Status: ENABLED (kernel module loaded)\n")
			} else {
				sb.WriteString("  [!] Status: DISABLED (module loaded but not enforcing)\n")
			}
		}

		// Read mode
		if data, err := os.ReadFile("/sys/module/apparmor/parameters/mode"); err == nil {
			mode := strings.TrimSpace(string(data))
			structs.ZeroBytes(data)
			sb.WriteString(fmt.Sprintf("  Mode: %s\n", mode))
		}

		// Count loaded profiles
		if data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles"); err == nil {
			content := string(data)
			structs.ZeroBytes(data)
			var enforce, complain, unconfined int
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if strings.Contains(line, "(enforce)") {
					enforce++
				} else if strings.Contains(line, "(complain)") {
					complain++
				} else {
					unconfined++
				}
			}
			sb.WriteString(fmt.Sprintf("  Profiles: %d enforce, %d complain, %d other\n", enforce, complain, unconfined))
			if complain > 0 {
				sb.WriteString(fmt.Sprintf("  [!] %d profiles in COMPLAIN mode — violations logged but not blocked\n", complain))
			}
		}
	}

	if !appArmorFound {
		sb.WriteString("  Not installed/loaded\n")
	}

	// --- SELinux ---
	sb.WriteString("\nSELinux:\n")
	selinuxFound := false

	// Check SELinux status via /sys/fs/selinux/enforce
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		selinuxFound = true
		enforce := strings.TrimSpace(string(data))
		structs.ZeroBytes(data)
		switch enforce {
		case "1":
			sb.WriteString("  Status: ENFORCING\n")
		case "0":
			sb.WriteString("  [!] Status: PERMISSIVE — violations logged but not blocked\n")
		default:
			sb.WriteString(fmt.Sprintf("  Status: unknown (%s)\n", enforce))
		}
	}

	// Check SELinux config file for persistent setting
	if data, err := os.ReadFile("/etc/selinux/config"); err == nil {
		content := string(data)
		structs.ZeroBytes(data)
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "SELINUX=") {
				value := strings.TrimPrefix(line, "SELINUX=")
				sb.WriteString(fmt.Sprintf("  Config: %s\n", value))
				switch value {
				case "disabled":
					sb.WriteString("  [!] SELinux is DISABLED in config — no mandatory access control\n")
				case "permissive":
					sb.WriteString("  [!] SELinux is PERMISSIVE in config — violations logged but not blocked\n")
				}
			}
			if strings.HasPrefix(line, "SELINUXTYPE=") {
				sb.WriteString(fmt.Sprintf("  Policy: %s\n", strings.TrimPrefix(line, "SELINUXTYPE=")))
			}
		}
	}

	if !selinuxFound {
		if _, err := os.Stat("/etc/selinux"); os.IsNotExist(err) {
			sb.WriteString("  Not installed\n")
		} else {
			sb.WriteString("  Installed but not active\n")
		}
	}

	// --- Summary ---
	if !appArmorFound && !selinuxFound {
		sb.WriteString("\n[!] No mandatory access control (MAC) system active — reduced security posture")
	}

	return successResult(sb.String())
}
