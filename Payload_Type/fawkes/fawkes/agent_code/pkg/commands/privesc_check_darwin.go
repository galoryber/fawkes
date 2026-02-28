//go:build darwin

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type PrivescCheckCommand struct{}

func (c *PrivescCheckCommand) Name() string {
	return "privesc-check"
}

func (c *PrivescCheckCommand) Description() string {
	return "macOS privilege escalation enumeration: SUID/SGID binaries, sudo rules, writable LaunchDaemons/Agents, TCC database, dylib hijacking, SIP status (T1548)"
}

type privescCheckArgs struct {
	Action string `json:"action"`
}

func (c *PrivescCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args privescCheckArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "all"
	}

	switch strings.ToLower(args.Action) {
	case "all":
		return macPrivescCheckAll()
	case "suid":
		return macPrivescCheckSUID()
	case "sudo":
		return macPrivescCheckSudo()
	case "launchdaemons":
		return macPrivescCheckLaunchDaemons()
	case "tcc":
		return macPrivescCheckTCC()
	case "dylib":
		return macPrivescCheckDylib()
	case "sip":
		return macPrivescCheckSIP()
	case "writable":
		return macPrivescCheckWritable()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: all, suid, sudo, launchdaemons, tcc, dylib, sip, writable", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func macPrivescCheckAll() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== macOS PRIVILEGE ESCALATION CHECK ===\n\n")

	sb.WriteString("--- SIP Status ---\n")
	sb.WriteString(macPrivescCheckSIP().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- SUID/SGID Binaries ---\n")
	sb.WriteString(macPrivescCheckSUID().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Sudo Rules ---\n")
	sb.WriteString(macPrivescCheckSudo().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- LaunchDaemons / LaunchAgents ---\n")
	sb.WriteString(macPrivescCheckLaunchDaemons().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- TCC Database ---\n")
	sb.WriteString(macPrivescCheckTCC().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Dylib Hijacking ---\n")
	sb.WriteString(macPrivescCheckDylib().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Writable Paths ---\n")
	sb.WriteString(macPrivescCheckWritable().Output)

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// macPrivescCheckSIP checks System Integrity Protection status
func macPrivescCheckSIP() structs.CommandResult {
	var sb strings.Builder

	out, err := exec.Command("csrutil", "status").CombinedOutput()
	if err != nil {
		sb.WriteString(fmt.Sprintf("csrutil status failed: %v\n", err))
	} else {
		output := strings.TrimSpace(string(out))
		sb.WriteString(output + "\n")
		if strings.Contains(output, "disabled") {
			sb.WriteString("[!] SIP is DISABLED — kernel extensions, unsigned code, and system modification possible\n")
		} else if strings.Contains(output, "enabled") {
			sb.WriteString("[*] SIP is enabled — standard protections active\n")
		}
	}

	// Check Authenticated Root (macOS 11+)
	out, err = exec.Command("csrutil", "authenticated-root", "status").CombinedOutput()
	if err == nil {
		output := strings.TrimSpace(string(out))
		if output != "" {
			sb.WriteString(output + "\n")
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// macPrivescCheckSUID finds SUID and SGID binaries
func macPrivescCheckSUID() structs.CommandResult {
	var sb strings.Builder
	var suidFiles []string
	var sgidFiles []string

	searchPaths := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"/bin", "/sbin", "/opt/homebrew/bin", "/opt/local/bin"}

	for _, searchPath := range searchPaths {
		_ = filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			mode := info.Mode()
			if mode&os.ModeSetuid != 0 {
				suidFiles = append(suidFiles, fmt.Sprintf("  %s (%s, %d bytes)", path, mode.String(), info.Size()))
			}
			if mode&os.ModeSetgid != 0 {
				sgidFiles = append(sgidFiles, fmt.Sprintf("  %s (%s, %d bytes)", path, mode.String(), info.Size()))
			}
			return nil
		})
	}

	sb.WriteString(fmt.Sprintf("SUID binaries (%d found):\n", len(suidFiles)))
	if len(suidFiles) > 0 {
		sb.WriteString(strings.Join(suidFiles, "\n"))
	} else {
		sb.WriteString("  (none found)")
	}

	sb.WriteString(fmt.Sprintf("\n\nSGID binaries (%d found):\n", len(sgidFiles)))
	if len(sgidFiles) > 0 {
		sb.WriteString(strings.Join(sgidFiles, "\n"))
	} else {
		sb.WriteString("  (none found)")
	}

	// Flag interesting SUID binaries
	interestingBins := []string{"nmap", "vim", "vi", "nano", "find", "bash", "sh", "zsh",
		"env", "python", "python3", "perl", "ruby", "node", "lua", "awk",
		"less", "more", "ftp", "socat", "nc", "ncat", "wget", "curl",
		"gcc", "make", "docker", "mount", "umount", "screen", "tmux",
		"cp", "mv", "dd", "tee", "rsync", "tar", "zip", "unzip",
		"doas", "openssl", "php", "ssh-keygen", "at", "crontab"}

	var flagged []string
	for _, f := range suidFiles {
		for _, bin := range interestingBins {
			if strings.Contains(f, "/"+bin+" ") || strings.HasSuffix(strings.Fields(f)[0], "/"+bin) {
				flagged = append(flagged, f)
				break
			}
		}
	}

	if len(flagged) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n[!] INTERESTING SUID binaries (%d):\n", len(flagged)))
		sb.WriteString(strings.Join(flagged, "\n"))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// macPrivescCheckSudo checks sudo rules
func macPrivescCheckSudo() structs.CommandResult {
	var sb strings.Builder

	out, err := exec.Command("sudo", "-n", "-l").CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if strings.Contains(output, "password is required") || strings.Contains(output, "a password is required") {
			sb.WriteString("sudo -l requires a password (non-interactive mode failed)\n")
			sb.WriteString("This means the user has sudo rules but needs authentication.\n")
		} else if strings.Contains(output, "not allowed") || strings.Contains(output, "not in the sudoers") {
			sb.WriteString("User is NOT in sudoers file.\n")
		} else {
			sb.WriteString(fmt.Sprintf("sudo -l failed: %v\n%s\n", err, output))
		}
	} else {
		sb.WriteString(output + "\n")
		if strings.Contains(output, "NOPASSWD") {
			sb.WriteString("\n[!] NOPASSWD rules detected — potential passwordless privilege escalation")
		}
		if strings.Contains(output, "(ALL : ALL) ALL") || strings.Contains(output, "(ALL) ALL") {
			sb.WriteString("\n[!] User has full sudo access (ALL)")
		}
	}

	// Check if /etc/sudoers is readable
	if data, err := os.ReadFile("/etc/sudoers"); err == nil {
		sb.WriteString("\n\n/etc/sudoers is READABLE (unusual):\n")
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				sb.WriteString("  " + line + "\n")
			}
		}
	}

	// Check group memberships that grant admin
	out, _ = exec.Command("id").CombinedOutput()
	idOutput := strings.TrimSpace(string(out))
	sb.WriteString(fmt.Sprintf("\nCurrent identity: %s\n", idOutput))
	if strings.Contains(idOutput, "(admin)") || strings.Contains(idOutput, "(wheel)") {
		sb.WriteString("[*] User is in admin/wheel group — may have sudo access with password\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// macPrivescCheckLaunchDaemons checks for writable LaunchDaemons and LaunchAgents
func macPrivescCheckLaunchDaemons() structs.CommandResult {
	var sb strings.Builder

	homeDir, _ := os.UserHomeDir()

	// LaunchDaemon/Agent directories to check
	dirs := []struct {
		path     string
		desc     string
		elevated bool // true = runs as root
	}{
		{"/Library/LaunchDaemons", "System LaunchDaemons (run as root)", true},
		{"/Library/LaunchAgents", "System LaunchAgents (run as logged-in users)", false},
		{"/System/Library/LaunchDaemons", "Apple LaunchDaemons (SIP-protected)", true},
		{"/System/Library/LaunchAgents", "Apple LaunchAgents (SIP-protected)", false},
	}
	if homeDir != "" {
		dirs = append(dirs, struct {
			path     string
			desc     string
			elevated bool
		}{filepath.Join(homeDir, "Library/LaunchAgents"), "User LaunchAgents", false})
	}

	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}

		var writable []string
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}
			plistPath := filepath.Join(d.path, entry.Name())
			if macIsWritable(plistPath) {
				writable = append(writable, fmt.Sprintf("  [!] %s", plistPath))
			}
		}

		sb.WriteString(fmt.Sprintf("%s (%s, %d plists):\n", d.path, d.desc, len(entries)))
		if len(writable) > 0 {
			sb.WriteString(fmt.Sprintf("  [!] %d WRITABLE plists found:\n", len(writable)))
			sb.WriteString(strings.Join(writable, "\n") + "\n")
			if d.elevated {
				sb.WriteString("  [!!] Writable root-level LaunchDaemon — HIGH IMPACT: modify to execute as root\n")
			}
		}
	}

	// Check if /Library/LaunchDaemons directory itself is writable
	if macIsWritable("/Library/LaunchDaemons") {
		sb.WriteString("\n[!!] /Library/LaunchDaemons is WRITABLE — can create new root-level persistence\n")
	}
	if macIsWritable("/Library/LaunchAgents") {
		sb.WriteString("[!] /Library/LaunchAgents is WRITABLE — can create user-level persistence\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// macPrivescCheckTCC inspects TCC database for permission grants
func macPrivescCheckTCC() structs.CommandResult {
	var sb strings.Builder

	homeDir, _ := os.UserHomeDir()

	// TCC databases
	tccPaths := []struct {
		path string
		desc string
	}{
		{"/Library/Application Support/com.apple.TCC/TCC.db", "System TCC (root-managed)"},
	}
	if homeDir != "" {
		tccPaths = append(tccPaths, struct {
			path string
			desc string
		}{filepath.Join(homeDir, "Library/Application Support/com.apple.TCC/TCC.db"), "User TCC"})
	}

	for _, tcc := range tccPaths {
		info, err := os.Stat(tcc.path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s: not accessible\n", tcc.desc))
			continue
		}
		sb.WriteString(fmt.Sprintf("%s: %s (%s)\n", tcc.desc, tcc.path, info.Mode().String()))

		// Try reading with sqlite3
		out, err := exec.Command("sqlite3", tcc.path,
			"SELECT service, client, auth_value, auth_reason FROM access WHERE auth_value > 0 ORDER BY service;").CombinedOutput()
		if err != nil {
			sb.WriteString(fmt.Sprintf("  Cannot query (expected if not root): %v\n", err))
			continue
		}

		output := strings.TrimSpace(string(out))
		if output == "" {
			sb.WriteString("  No granted permissions found.\n")
			continue
		}

		// Parse and format results
		interesting := 0
		scanner := bufio.NewScanner(strings.NewReader(output))
		for scanner.Scan() {
			fields := strings.SplitN(scanner.Text(), "|", 4)
			if len(fields) < 3 {
				continue
			}
			service := fields[0]
			client := fields[1]
			authVal := fields[2]

			// Flag high-value permissions
			flag := ""
			switch service {
			case "kTCCServiceAccessibility":
				flag = " [!] Accessibility — can control UI, inject keystrokes"
			case "kTCCServiceScreenCapture":
				flag = " [!] Screen Capture"
			case "kTCCServiceSystemPolicyAllFiles":
				flag = " [!] Full Disk Access"
			case "kTCCServiceMicrophone":
				flag = " [!] Microphone Access"
			case "kTCCServiceCamera":
				flag = " [!] Camera Access"
			}
			sb.WriteString(fmt.Sprintf("  %s → %s (auth=%s)%s\n", service, client, authVal, flag))
			if flag != "" {
				interesting++
			}
		}
		if interesting > 0 {
			sb.WriteString(fmt.Sprintf("  [*] %d high-value permission grants found\n", interesting))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// macPrivescCheckDylib checks for dylib hijacking opportunities
func macPrivescCheckDylib() structs.CommandResult {
	var sb strings.Builder

	// Check DYLD_* environment variables
	dyldVars := []string{"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FORCE_FLAT_NAMESPACE"}

	for _, env := range dyldVars {
		if val := os.Getenv(env); val != "" {
			sb.WriteString(fmt.Sprintf("[!] %s=%s\n", env, val))
		}
	}

	// Check if Hardened Runtime is common (look at a few key binaries)
	binaries := []string{"/usr/bin/ssh", "/usr/bin/sudo", "/usr/bin/login"}
	for _, bin := range binaries {
		out, err := exec.Command("codesign", "-dv", bin).CombinedOutput()
		if err == nil {
			output := string(out)
			if strings.Contains(output, "runtime") {
				sb.WriteString(fmt.Sprintf("  %s: Hardened Runtime (DYLD injection blocked)\n", bin))
			} else {
				sb.WriteString(fmt.Sprintf("  [!] %s: NO Hardened Runtime (DYLD injection possible)\n", bin))
			}
		}
	}

	// Check for writable directories in common library paths
	libPaths := []string{"/usr/local/lib", "/opt/homebrew/lib", "/Library/Frameworks"}
	for _, p := range libPaths {
		if macIsWritable(p) {
			sb.WriteString(fmt.Sprintf("[!] %s is WRITABLE — dylib planting possible\n", p))
		}
	}

	// Check for unsigned or ad-hoc signed applications
	appDirs := []string{"/Applications"}
	for _, dir := range appDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var unsigned []string
		count := 0
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".app") {
				continue
			}
			count++
			appPath := filepath.Join(dir, entry.Name())
			out, err := exec.Command("codesign", "-v", appPath).CombinedOutput()
			if err != nil {
				output := string(out)
				if strings.Contains(output, "not signed") || strings.Contains(output, "invalid signature") {
					unsigned = append(unsigned, fmt.Sprintf("  [!] %s", appPath))
				}
			}
			if count >= 20 { // Limit to avoid slow scans
				break
			}
		}
		if len(unsigned) > 0 {
			sb.WriteString(fmt.Sprintf("\nUnsigned/invalid apps in %s (%d):\n", dir, len(unsigned)))
			sb.WriteString(strings.Join(unsigned, "\n") + "\n")
		}
	}

	if sb.Len() == 0 {
		sb.WriteString("No obvious dylib hijacking vectors found.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// macPrivescCheckWritable checks for writable sensitive paths
func macPrivescCheckWritable() structs.CommandResult {
	var sb strings.Builder

	// Check PATH directories for write access
	pathDirs := strings.Split(os.Getenv("PATH"), ":")
	var writablePATH []string
	for _, dir := range pathDirs {
		if dir == "" {
			continue
		}
		if macIsWritable(dir) {
			writablePATH = append(writablePATH, "  "+dir)
		}
	}

	sb.WriteString(fmt.Sprintf("Writable PATH directories (%d):\n", len(writablePATH)))
	if len(writablePATH) > 0 {
		sb.WriteString(strings.Join(writablePATH, "\n") + "\n")
		sb.WriteString("[!] Writable PATH directories enable binary hijacking\n")
	} else {
		sb.WriteString("  (none — PATH is clean)\n")
	}

	// Sensitive macOS paths
	sensitiveFiles := map[string]string{
		"/etc/passwd":                            "User database",
		"/etc/sudoers":                           "Sudo configuration",
		"/etc/authorization":                     "Authorization policy",
		"/private/etc/pam.d":                     "PAM configuration",
		"/Library/Preferences":                   "System preferences",
		"/Library/Security/SecurityAgentPlugins": "Security agent plugins (root)",
	}

	var writable, readable []string
	for path, desc := range sensitiveFiles {
		if macIsWritable(path) {
			info, _ := os.Stat(path)
			mode := "?"
			if info != nil {
				mode = info.Mode().String()
			}
			writable = append(writable, fmt.Sprintf("  %s — %s (%s)", path, desc, mode))
		} else if path == "/etc/sudoers" || path == "/etc/authorization" {
			if f, err := os.Open(path); err == nil {
				f.Close()
				info, _ := os.Stat(path)
				mode := "?"
				if info != nil {
					mode = info.Mode().String()
				}
				readable = append(readable, fmt.Sprintf("  %s — %s (%s)", path, desc, mode))
			}
		}
	}

	if len(writable) > 0 {
		sb.WriteString(fmt.Sprintf("\n[!] WRITABLE sensitive paths (%d):\n", len(writable)))
		sb.WriteString(strings.Join(writable, "\n") + "\n")
	}
	if len(readable) > 0 {
		sb.WriteString(fmt.Sprintf("\nReadable sensitive files (%d):\n", len(readable)))
		sb.WriteString(strings.Join(readable, "\n") + "\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// macIsWritable checks if the current user can write to a path
func macIsWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		tmpFile := filepath.Join(path, ".fawkes_write_test")
		f, err := os.Create(tmpFile)
		if err != nil {
			return false
		}
		f.Close()
		os.Remove(tmpFile)
		return true
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
