//go:build linux

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
	return "Linux privilege escalation enumeration: SUID/SGID binaries, capabilities, sudo rules, writable paths, container detection (T1548)"
}

type privescCheckArgs struct {
	Action string `json:"action"`
}

func (c *PrivescCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args privescCheckArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Plain text fallback: "suid", "capabilities", "sudo", "writable", "container", "all"
			args.Action = strings.TrimSpace(task.Params)
		}
	}

	if args.Action == "" {
		args.Action = "all"
	}

	switch strings.ToLower(args.Action) {
	case "all":
		return privescCheckAll()
	case "suid":
		return privescCheckSUID()
	case "capabilities":
		return privescCheckCapabilities()
	case "sudo":
		return privescCheckSudo()
	case "writable":
		return privescCheckWritable()
	case "container":
		return privescCheckContainer()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: all, suid, capabilities, sudo, writable, container", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// privescCheckAll runs all checks and returns a combined report
func privescCheckAll() structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("=== LINUX PRIVILEGE ESCALATION CHECK ===\n\n")

	// SUID/SGID
	sb.WriteString("--- SUID/SGID Binaries ---\n")
	suidResult := privescCheckSUID()
	sb.WriteString(suidResult.Output)
	sb.WriteString("\n\n")

	// Capabilities
	sb.WriteString("--- File Capabilities ---\n")
	capResult := privescCheckCapabilities()
	sb.WriteString(capResult.Output)
	sb.WriteString("\n\n")

	// Sudo
	sb.WriteString("--- Sudo Rules ---\n")
	sudoResult := privescCheckSudo()
	sb.WriteString(sudoResult.Output)
	sb.WriteString("\n\n")

	// Writable paths
	sb.WriteString("--- Writable Paths ---\n")
	writableResult := privescCheckWritable()
	sb.WriteString(writableResult.Output)
	sb.WriteString("\n\n")

	// Container detection
	sb.WriteString("--- Container Detection ---\n")
	containerResult := privescCheckContainer()
	sb.WriteString(containerResult.Output)

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// privescCheckSUID finds SUID and SGID binaries
func privescCheckSUID() structs.CommandResult {
	var sb strings.Builder
	var suidFiles []string
	var sgidFiles []string

	// Walk common binary paths for SUID/SGID
	searchPaths := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"/bin", "/sbin", "/snap"}

	for _, searchPath := range searchPaths {
		_ = filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip permission errors
			}
			if info.IsDir() {
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

	// Flag interesting SUID binaries that are commonly exploitable
	interestingBins := []string{"nmap", "vim", "vi", "nano", "find", "bash", "sh", "dash",
		"env", "python", "python3", "perl", "ruby", "node", "lua", "awk", "gawk",
		"less", "more", "man", "ftp", "socat", "nc", "ncat", "wget", "curl",
		"gcc", "g++", "make", "docker", "pkexec", "mount", "umount",
		"systemctl", "journalctl", "strace", "ltrace", "gdb", "screen", "tmux",
		"cp", "mv", "dd", "tee", "rsync", "tar", "zip", "unzip", "busybox",
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

// privescCheckCapabilities finds binaries with Linux capabilities set
func privescCheckCapabilities() structs.CommandResult {
	var sb strings.Builder

	// Try getcap on common paths
	out, err := exec.Command("getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin").CombinedOutput()
	if err != nil {
		// getcap might not be available, or might fail on some dirs
		// Try alternative: read /proc/self/status for current process capabilities
		sb.WriteString("getcap output (partial — errors on inaccessible paths are normal):\n")
	}

	output := strings.TrimSpace(string(out))
	if output != "" {
		sb.WriteString(output)
	} else {
		sb.WriteString("  (no capabilities found or getcap not available)")
	}

	// Current process capabilities
	sb.WriteString("\n\nCurrent process capabilities:\n")
	capData, err := os.ReadFile("/proc/self/status")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(capData)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Cap") {
				sb.WriteString("  " + line + "\n")
			}
		}
	} else {
		sb.WriteString(fmt.Sprintf("  (error reading /proc/self/status: %v)", err))
	}

	// Interesting capabilities to flag
	interestingCaps := []string{"cap_sys_admin", "cap_sys_ptrace", "cap_dac_override",
		"cap_dac_read_search", "cap_setuid", "cap_setgid", "cap_net_raw",
		"cap_net_admin", "cap_net_bind_service", "cap_sys_module", "cap_fowner",
		"cap_chown", "cap_sys_chroot"}

	if output != "" {
		var flagged []string
		for _, line := range strings.Split(output, "\n") {
			lower := strings.ToLower(line)
			for _, cap := range interestingCaps {
				if strings.Contains(lower, cap) {
					flagged = append(flagged, "  "+strings.TrimSpace(line))
					break
				}
			}
		}
		if len(flagged) > 0 {
			sb.WriteString(fmt.Sprintf("\n[!] INTERESTING capabilities (%d):\n", len(flagged)))
			sb.WriteString(strings.Join(flagged, "\n"))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// privescCheckSudo enumerates sudo rules for the current user
func privescCheckSudo() structs.CommandResult {
	var sb strings.Builder

	// Try sudo -l (may require password — handle gracefully)
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
		sb.WriteString(output)
		sb.WriteString("\n")

		// Flag NOPASSWD entries
		if strings.Contains(output, "NOPASSWD") {
			sb.WriteString("\n[!] NOPASSWD rules detected — potential passwordless privilege escalation")
		}
		// Flag ALL entries
		if strings.Contains(output, "(ALL : ALL) ALL") || strings.Contains(output, "(ALL) ALL") {
			sb.WriteString("\n[!] User has full sudo access (ALL)")
		}
	}

	// Check if /etc/sudoers is readable
	if data, err := os.ReadFile("/etc/sudoers"); err == nil {
		sb.WriteString("\n\n/etc/sudoers is READABLE (unusual — potential misconfiguration):\n")
		// Show non-comment, non-empty lines
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		lineCount := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				sb.WriteString("  " + line + "\n")
				lineCount++
			}
		}
		if lineCount == 0 {
			sb.WriteString("  (no active rules)")
		}
	}

	// Check sudoers.d
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		var readableFiles []string
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join("/etc/sudoers.d", entry.Name())
			if data, err := os.ReadFile(path); err == nil {
				readableFiles = append(readableFiles, fmt.Sprintf("  %s:\n    %s",
					path, strings.ReplaceAll(strings.TrimSpace(string(data)), "\n", "\n    ")))
			}
		}
		if len(readableFiles) > 0 {
			sb.WriteString(fmt.Sprintf("\n\nReadable /etc/sudoers.d files (%d):\n", len(readableFiles)))
			sb.WriteString(strings.Join(readableFiles, "\n"))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// privescCheckWritable finds world-writable directories in PATH and other sensitive locations
func privescCheckWritable() structs.CommandResult {
	var sb strings.Builder

	// Check PATH directories for write access
	pathDirs := strings.Split(os.Getenv("PATH"), ":")
	var writablePATH []string
	for _, dir := range pathDirs {
		if dir == "" {
			continue
		}
		if isWritable(dir) {
			writablePATH = append(writablePATH, "  "+dir)
		}
	}

	sb.WriteString(fmt.Sprintf("Writable PATH directories (%d):\n", len(writablePATH)))
	if len(writablePATH) > 0 {
		sb.WriteString(strings.Join(writablePATH, "\n"))
		sb.WriteString("\n[!] Writable PATH directories enable binary hijacking")
	} else {
		sb.WriteString("  (none — PATH is clean)")
	}

	// Check world-writable directories
	worldWritable := []string{"/tmp", "/var/tmp", "/dev/shm"}
	var writableDirs []string
	for _, dir := range worldWritable {
		if info, err := os.Stat(dir); err == nil {
			if info.Mode().Perm()&0002 != 0 {
				writableDirs = append(writableDirs, fmt.Sprintf("  %s (world-writable)", dir))
			}
		}
	}
	sb.WriteString(fmt.Sprintf("\n\nWorld-writable directories (%d):\n", len(writableDirs)))
	if len(writableDirs) > 0 {
		sb.WriteString(strings.Join(writableDirs, "\n"))
	} else {
		sb.WriteString("  (none found)")
	}

	// Check sensitive file permissions
	sensitiveFiles := map[string]string{
		"/etc/passwd":  "User database",
		"/etc/shadow":  "Password hashes",
		"/etc/group":   "Group memberships",
		"/etc/sudoers": "Sudo configuration",
		"/etc/crontab": "System cron jobs",
		"/root":        "Root home directory",
	}

	var readable, writable []string
	for path, desc := range sensitiveFiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if isWritable(path) {
			writable = append(writable, fmt.Sprintf("  %s — %s (%s)", path, desc, info.Mode().String()))
		} else if isReadable(path) {
			if path == "/etc/shadow" || path == "/etc/sudoers" || path == "/root" {
				readable = append(readable, fmt.Sprintf("  %s — %s (%s)", path, desc, info.Mode().String()))
			}
		}
	}

	if len(writable) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n[!] WRITABLE sensitive files (%d):\n", len(writable)))
		sb.WriteString(strings.Join(writable, "\n"))
	}
	if len(readable) > 0 {
		sb.WriteString(fmt.Sprintf("\n\nReadable sensitive files (%d):\n", len(readable)))
		sb.WriteString(strings.Join(readable, "\n"))
	}

	// Check /etc/passwd for unusual shells or UID 0 accounts
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		var uid0 []string
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) >= 4 && fields[2] == "0" && fields[0] != "root" {
				uid0 = append(uid0, "  "+scanner.Text())
			}
		}
		if len(uid0) > 0 {
			sb.WriteString(fmt.Sprintf("\n\n[!] NON-ROOT accounts with UID 0 (%d):\n", len(uid0)))
			sb.WriteString(strings.Join(uid0, "\n"))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// privescCheckContainer detects if running inside a container
func privescCheckContainer() structs.CommandResult {
	var sb strings.Builder
	containerFound := false

	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		sb.WriteString("[!] DOCKER DETECTED — /.dockerenv exists\n")
		containerFound = true
	}

	// Check for Podman/other container runtimes
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		sb.WriteString("[!] CONTAINER DETECTED — /run/.containerenv exists\n")
		if data, err := os.ReadFile("/run/.containerenv"); err == nil && len(data) > 0 {
			sb.WriteString(fmt.Sprintf("  Container env: %s\n", strings.TrimSpace(string(data))))
		}
		containerFound = true
	}

	// Check cgroup for container indicators
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "kubepods") ||
			strings.Contains(content, "lxc") || strings.Contains(content, "containerd") {
			sb.WriteString("[!] CONTAINER DETECTED via /proc/1/cgroup\n")
			containerFound = true
		}
		sb.WriteString("PID 1 cgroups:\n")
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				sb.WriteString("  " + line + "\n")
			}
		}
	}

	// Check for Kubernetes service account
	if _, err := os.Stat("/var/run/secrets/kubernetes.io"); err == nil {
		sb.WriteString("\n[!] KUBERNETES POD — service account secrets found at /var/run/secrets/kubernetes.io/\n")
		containerFound = true

		// Read service account token
		if token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
			// Just show first 40 chars for confirmation
			tokenStr := string(token)
			if len(tokenStr) > 40 {
				tokenStr = tokenStr[:40] + "..."
			}
			sb.WriteString(fmt.Sprintf("  Token: %s\n", tokenStr))
		}
		if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			sb.WriteString(fmt.Sprintf("  Namespace: %s\n", strings.TrimSpace(string(ns))))
		}
	}

	// Check for Docker socket
	if info, err := os.Stat("/var/run/docker.sock"); err == nil {
		sb.WriteString(fmt.Sprintf("\n[!] DOCKER SOCKET found: /var/run/docker.sock (%s)\n", info.Mode().String()))
		if isWritable("/var/run/docker.sock") {
			sb.WriteString("  [!!] Socket is WRITABLE — possible container escape via docker!\n")
		}
		containerFound = true
	}

	// Check PID 1 process name
	if data, err := os.ReadFile("/proc/1/comm"); err == nil {
		comm := strings.TrimSpace(string(data))
		sb.WriteString(fmt.Sprintf("\nPID 1 process: %s\n", comm))
		if comm != "systemd" && comm != "init" {
			sb.WriteString("  [!] Unusual PID 1 — may indicate container (expected systemd/init on host)\n")
			containerFound = true
		}
	}

	// Check hostname — containers often have random hex names
	if hostname, err := os.Hostname(); err == nil {
		sb.WriteString(fmt.Sprintf("Hostname: %s\n", hostname))
	}

	// Check mount namespace
	if data, err := os.ReadFile("/proc/1/mountinfo"); err == nil {
		content := string(data)
		if strings.Contains(content, "overlay") || strings.Contains(content, "aufs") {
			sb.WriteString("[!] Overlay/AUFS filesystem detected — consistent with container\n")
			containerFound = true
		}
	}

	if !containerFound {
		sb.WriteString("No container indicators found — likely running on bare metal/VM host.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// isWritable checks if the current user can write to a path
func isWritable(path string) bool {
	// Try creating a temp file
	tmpFile := filepath.Join(path, ".fawkes_write_test")
	f, err := os.Create(tmpFile)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(tmpFile)
	return true
}

// isReadable checks if the current user can read a path
func isReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
