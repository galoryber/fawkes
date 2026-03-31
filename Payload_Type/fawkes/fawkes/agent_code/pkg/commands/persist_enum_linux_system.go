//go:build linux

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// persistEnumPreload checks LD_PRELOAD and ld.so.preload.
func persistEnumPreload(sb *strings.Builder) int {
	sb.WriteString("--- LD_PRELOAD / ld.so.preload ---\n")
	count := 0

	// Check /etc/ld.so.preload
	if content, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [ld.so.preload] %s\n", line))
			count++
		}
	}

	// Check LD_PRELOAD environment variable
	if ldPreload := os.Getenv("LD_PRELOAD"); ldPreload != "" {
		sb.WriteString(fmt.Sprintf("  [LD_PRELOAD] %s\n", ldPreload))
		count++
	}

	// Check /etc/environment for LD_PRELOAD
	if content, err := os.ReadFile("/etc/environment"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, "LD_PRELOAD") {
				sb.WriteString(fmt.Sprintf("  [/etc/environment] %s\n", strings.TrimSpace(line)))
				count++
			}
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumUdev checks for custom udev rules that can execute scripts on device events (T1546).
func persistEnumUdev(sb *strings.Builder) int {
	sb.WriteString("--- Udev Rules ---\n")
	count := 0

	udevDirs := []struct {
		path string
		desc string
	}{
		{"/etc/udev/rules.d", "custom"},
		{"/lib/udev/rules.d", "system"},
		{"/usr/lib/udev/rules.d", "vendor"},
	}

	for _, ud := range udevDirs {
		entries, err := os.ReadDir(ud.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
				continue
			}
			path := filepath.Join(ud.path, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [%s] %s (unreadable)\n", ud.desc, entry.Name()))
				count++
				continue
			}

			// Check for RUN= directives that execute programs
			hasRun := false
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.Contains(line, "RUN+=") || strings.Contains(line, "RUN=") ||
					strings.Contains(line, "PROGRAM=") {
					hasRun = true
					break
				}
			}

			if ud.desc == "custom" || hasRun {
				flag := ""
				if hasRun {
					flag = " [!] executes programs"
				}
				sb.WriteString(fmt.Sprintf("  [%s] %s%s\n", ud.desc, entry.Name(), flag))
				count++
			}
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumKernelModules checks for kernel modules configured to auto-load (T1547.006).
func persistEnumKernelModules(sb *strings.Builder) int {
	sb.WriteString("--- Kernel Modules (Auto-Load) ---\n")
	count := 0

	// /etc/modules — legacy file listing modules to load at boot
	if content, err := os.ReadFile("/etc/modules"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [/etc/modules] %s\n", line))
			count++
		}
	}

	// /etc/modules-load.d/ — systemd module loading
	if entries, err := os.ReadDir("/etc/modules-load.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join("/etc/modules-load.d", entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
					continue
				}
				sb.WriteString(fmt.Sprintf("  [modules-load.d/%s] %s\n", entry.Name(), line))
				count++
			}
		}
	}

	// /etc/modprobe.d/ — module options, blacklists, and install directives
	if entries, err := os.ReadDir("/etc/modprobe.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join("/etc/modprobe.d", entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				// Flag "install" directives — these run arbitrary commands when a module is loaded
				if strings.HasPrefix(line, "install ") {
					sb.WriteString(fmt.Sprintf("  [!] [modprobe.d/%s] %s\n", entry.Name(), line))
					count++
				}
			}
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumPAM checks for custom PAM modules that could intercept authentication (T1556.003).
func persistEnumPAM(sb *strings.Builder) int {
	sb.WriteString("--- PAM Configuration ---\n")
	count := 0

	// Check /etc/pam.d/ for custom modules
	pamDir := "/etc/pam.d"
	entries, err := os.ReadDir(pamDir)
	if err != nil {
		sb.WriteString("  (cannot read /etc/pam.d)\n\n")
		return 0
	}

	// Scan each PAM config for non-standard modules
	standardModules := map[string]bool{
		"pam_unix.so": true, "pam_deny.so": true, "pam_permit.so": true,
		"pam_env.so": true, "pam_limits.so": true, "pam_nologin.so": true,
		"pam_succeed_if.so": true, "pam_pwquality.so": true, "pam_faillock.so": true,
		"pam_systemd.so": true, "pam_systemd_home.so": true, "pam_keyinit.so": true,
		"pam_loginuid.so": true, "pam_selinux.so": true, "pam_namespace.so": true,
		"pam_console.so": true, "pam_tally2.so": true, "pam_securetty.so": true,
		"pam_access.so": true, "pam_time.so": true, "pam_motd.so": true,
		"pam_mail.so": true, "pam_lastlog.so": true, "pam_shells.so": true,
		"pam_cap.so": true, "pam_wheel.so": true, "pam_xauth.so": true,
		"pam_gnome_keyring.so": true, "pam_kwallet5.so": true, "pam_fprintd.so": true,
		"pam_sss.so": true, "pam_winbind.so": true, "pam_krb5.so": true,
		"pam_ldap.so": true, "pam_cracklib.so": true, "pam_ecryptfs.so": true,
		"pam_google_authenticator.so": true, "pam_umask.so": true,
	}

	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join(pamDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
				continue
			}

			// PAM line format: type control module-path [module-arguments]
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}

			moduleName := filepath.Base(fields[2])
			if !standardModules[moduleName] && strings.HasSuffix(moduleName, ".so") {
				sb.WriteString(fmt.Sprintf("  [!] [%s] %s uses non-standard module: %s\n", entry.Name(), fields[0], moduleName))
				count++
			}
		}
	}

	// Check for custom PAM libraries in non-standard locations
	pamLibDirs := []string{"/lib/security", "/lib/x86_64-linux-gnu/security", "/lib64/security"}
	for _, dir := range pamLibDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".so") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			// Flag recently modified PAM modules (within last 30 days)
			if info.ModTime().After(time.Now().AddDate(0, 0, -30)) {
				sb.WriteString(fmt.Sprintf("  [!] [%s] %s recently modified (%s)\n",
					dir, entry.Name(), info.ModTime().Format("2006-01-02 15:04")))
				count++
			}
		}
	}

	if count == 0 {
		sb.WriteString("  (all standard modules)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumPackageHooks checks for APT/dpkg hooks that execute commands (T1546).
func persistEnumPackageHooks(sb *strings.Builder) int {
	sb.WriteString("--- Package Manager Hooks ---\n")
	count := 0

	// APT hooks — /etc/apt/apt.conf.d/ files with Invoke directives
	aptDir := "/etc/apt/apt.conf.d"
	if entries, err := os.ReadDir(aptDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join(aptDir, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			// Look for hook directives
			contentStr := string(content)
			hasHook := false
			hookPatterns := []string{
				"Pre-Invoke", "Post-Invoke", "Pre-Install-Pkgs",
				"Post-Install-Pkgs", "DPkg::Pre-Invoke", "DPkg::Post-Invoke",
				"APT::Update::Post-Invoke", "APT::Update::Pre-Invoke",
			}
			for _, pattern := range hookPatterns {
				if strings.Contains(contentStr, pattern) {
					hasHook = true
					break
				}
			}

			if hasHook {
				sb.WriteString(fmt.Sprintf("  [!] [apt.conf.d] %s contains hook directives\n", entry.Name()))
				count++
			}
		}
	}

	// dpkg hooks — /etc/dpkg/dpkg.cfg.d/ and triggers in /var/lib/dpkg/triggers/
	dpkgDir := "/etc/dpkg/dpkg.cfg.d"
	if entries, err := os.ReadDir(dpkgDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [dpkg.cfg.d] %s\n", entry.Name()))
			count++
		}
	}

	// Yum/DNF plugins — /etc/yum/pluginconf.d/ or /etc/dnf/plugins/
	for _, plugDir := range []string{"/etc/yum/pluginconf.d", "/etc/dnf/plugins"} {
		entries, err := os.ReadDir(plugDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", filepath.Base(plugDir), entry.Name()))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumLogrotate checks logrotate configs for postrotate/prerotate scripts (T1053).
func persistEnumLogrotate(sb *strings.Builder) int {
	sb.WriteString("--- Logrotate Scripts ---\n")
	count := 0

	logrotateDir := "/etc/logrotate.d"
	entries, err := os.ReadDir(logrotateDir)
	if err != nil {
		sb.WriteString("  (cannot read /etc/logrotate.d)\n\n")
		return 0
	}

	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join(logrotateDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Scan for script blocks
		contentStr := string(content)
		hasScript := false
		for _, directive := range []string{"postrotate", "prerotate", "firstaction", "lastaction"} {
			if strings.Contains(contentStr, directive) {
				hasScript = true
				break
			}
		}

		if hasScript {
			sb.WriteString(fmt.Sprintf("  [!] %s contains script directives\n", entry.Name()))
			count++
		}
	}

	// Also check main /etc/logrotate.conf
	if content, err := os.ReadFile("/etc/logrotate.conf"); err == nil {
		for _, directive := range []string{"postrotate", "prerotate", "firstaction", "lastaction"} {
			if strings.Contains(string(content), directive) {
				sb.WriteString("  [!] /etc/logrotate.conf contains script directives\n")
				count++
				break
			}
		}
	}

	if count == 0 {
		sb.WriteString("  (no script directives found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumNetworkManager checks NetworkManager dispatcher scripts (T1546).
func persistEnumNetworkManager(sb *strings.Builder) int {
	sb.WriteString("--- NetworkManager Dispatcher ---\n")
	count := 0

	// Dispatcher scripts run when network events occur (connect, disconnect, up, down)
	dispatcherDirs := []string{
		"/etc/NetworkManager/dispatcher.d",
		"/etc/NetworkManager/dispatcher.d/pre-up.d",
		"/etc/NetworkManager/dispatcher.d/pre-down.d",
		"/etc/NetworkManager/dispatcher.d/no-wait.d",
		"/usr/lib/NetworkManager/dispatcher.d",
	}

	for _, dir := range dispatcherDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [%s] %s\n", filepath.Base(dir), entry.Name()))
				count++
				continue
			}

			// Check if executable
			execFlag := ""
			if info.Mode()&0111 != 0 {
				execFlag = " [executable]"
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s (%s)%s\n",
				filepath.Base(dir), entry.Name(), info.Mode().String(), execFlag))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}
