//go:build linux

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type PrivescCheckCommand struct{}

func (c *PrivescCheckCommand) Name() string {
	return "privesc-check"
}

func (c *PrivescCheckCommand) Description() string {
	return "Linux privilege escalation enumeration: SUID/SGID binaries, capabilities, sudo rules, writable paths, container detection, cron script hijacking, NFS no_root_squash, systemd unit hijacking, sudo token reuse, PATH hijacking, docker group (T1548)"
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
	case "cron":
		return privescCheckCronScripts()
	case "nfs":
		return privescCheckNFS()
	case "systemd":
		return privescCheckSystemdUnits()
	case "sudo-token":
		return privescCheckSudoToken()
	case "path-hijack":
		return privescCheckPathHijack()
	case "docker-group":
		return privescCheckDockerGroup()
	case "group":
		return privescCheckDangerousGroups()
	case "polkit":
		return privescCheckPolkit()
	case "modprobe":
		return privescCheckModprobe()
	default:
		return errorf("Unknown action: %s. Use: all, suid, capabilities, sudo, writable, container, cron, nfs, systemd, sudo-token, path-hijack, docker-group, group, polkit, modprobe", args.Action)
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
	sb.WriteString("\n\n")

	// Writable cron scripts
	sb.WriteString("--- Cron Script Hijacking ---\n")
	cronResult := privescCheckCronScripts()
	sb.WriteString(cronResult.Output)
	sb.WriteString("\n\n")

	// NFS no_root_squash
	sb.WriteString("--- NFS Shares ---\n")
	nfsResult := privescCheckNFS()
	sb.WriteString(nfsResult.Output)
	sb.WriteString("\n\n")

	// Writable systemd units
	sb.WriteString("--- Systemd Unit Hijacking ---\n")
	systemdResult := privescCheckSystemdUnits()
	sb.WriteString(systemdResult.Output)
	sb.WriteString("\n\n")

	// Sudo token reuse
	sb.WriteString("--- Sudo Token Reuse ---\n")
	sudoTokenResult := privescCheckSudoToken()
	sb.WriteString(sudoTokenResult.Output)
	sb.WriteString("\n\n")

	// PATH hijacking
	sb.WriteString("--- PATH Hijacking ---\n")
	pathResult := privescCheckPathHijack()
	sb.WriteString(pathResult.Output)
	sb.WriteString("\n\n")

	// Docker group
	sb.WriteString("--- Docker Group ---\n")
	dockerResult := privescCheckDockerGroup()
	sb.WriteString(dockerResult.Output)
	sb.WriteString("\n\n")

	// Dangerous group memberships
	sb.WriteString("--- Dangerous Groups ---\n")
	groupResult := privescCheckDangerousGroups()
	sb.WriteString(groupResult.Output)
	sb.WriteString("\n\n")

	// Polkit rules
	sb.WriteString("--- Polkit Rules ---\n")
	polkitResult := privescCheckPolkit()
	sb.WriteString(polkitResult.Output)
	sb.WriteString("\n\n")

	// Modprobe hooks
	sb.WriteString("--- Modprobe Hooks ---\n")
	modprobeResult := privescCheckModprobe()
	sb.WriteString(modprobeResult.Output)

	return successResult(sb.String())
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
		_ = filepath.WalkDir(searchPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // Skip permission errors
			}
			if d.IsDir() {
				return nil
			}
			t := d.Type()
			if t&os.ModeSetuid == 0 && t&os.ModeSetgid == 0 {
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
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
		fields := strings.Fields(f)
		if len(fields) == 0 {
			continue
		}
		for _, bin := range interestingBins {
			if strings.Contains(f, "/"+bin+" ") || strings.HasSuffix(fields[0], "/"+bin) {
				flagged = append(flagged, f)
				break
			}
		}
	}

	if len(flagged) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n[!] INTERESTING SUID binaries (%d):\n", len(flagged)))
		sb.WriteString(strings.Join(flagged, "\n"))
	}

	return successResult(sb.String())
}

// privescCheckCapabilities finds binaries with Linux capabilities set.
// Uses native xattr reading instead of spawning getcap (OPSEC: no child process).
func privescCheckCapabilities() structs.CommandResult {
	var sb strings.Builder

	// Scan common binary paths for files with security.capability xattr
	searchPaths := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"/bin", "/sbin"}

	var capEntries []string
	for _, searchPath := range searchPaths {
		_ = filepath.WalkDir(searchPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			capStr := readFileCaps(path)
			if capStr != "" {
				capEntries = append(capEntries, fmt.Sprintf("  %s %s", path, capStr))
			}
			return nil
		})
	}

	sb.WriteString(fmt.Sprintf("File capabilities (%d found):\n", len(capEntries)))
	if len(capEntries) > 0 {
		sb.WriteString(strings.Join(capEntries, "\n"))
	} else {
		sb.WriteString("  (no capabilities found)")
	}

	// Current process capabilities from /proc/self/status
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
		structs.ZeroBytes(capData)
	} else {
		sb.WriteString(fmt.Sprintf("  (error reading /proc/self/status: %v)", err))
	}

	// Flag interesting capabilities
	interestingCaps := []string{"cap_sys_admin", "cap_sys_ptrace", "cap_dac_override",
		"cap_dac_read_search", "cap_setuid", "cap_setgid", "cap_net_raw",
		"cap_net_admin", "cap_net_bind_service", "cap_sys_module", "cap_fowner",
		"cap_chown", "cap_sys_chroot"}

	var flagged []string
	for _, entry := range capEntries {
		lower := strings.ToLower(entry)
		for _, cap := range interestingCaps {
			if strings.Contains(lower, cap) {
				flagged = append(flagged, entry)
				break
			}
		}
	}
	if len(flagged) > 0 {
		sb.WriteString(fmt.Sprintf("\n[!] INTERESTING capabilities (%d):\n", len(flagged)))
		sb.WriteString(strings.Join(flagged, "\n"))
	}

	return successResult(sb.String())
}

// capNames maps capability bit positions to names (Linux capability constants).
var capNames = [...]string{
	0: "cap_chown", 1: "cap_dac_override", 2: "cap_dac_read_search",
	3: "cap_fowner", 4: "cap_fsetid", 5: "cap_kill",
	6: "cap_setgid", 7: "cap_setuid", 8: "cap_setpcap",
	9: "cap_linux_immutable", 10: "cap_net_bind_service", 11: "cap_net_broadcast",
	12: "cap_net_admin", 13: "cap_net_raw", 14: "cap_ipc_lock",
	15: "cap_ipc_owner", 16: "cap_sys_module", 17: "cap_sys_rawio",
	18: "cap_sys_chroot", 19: "cap_sys_ptrace", 20: "cap_sys_pacct",
	21: "cap_sys_admin", 22: "cap_sys_boot", 23: "cap_sys_nice",
	24: "cap_sys_resource", 25: "cap_sys_time", 26: "cap_sys_tty_config",
	27: "cap_mknod", 28: "cap_lease", 29: "cap_audit_write",
	30: "cap_audit_control", 31: "cap_setfcap", 32: "cap_mac_override",
	33: "cap_mac_admin", 34: "cap_syslog", 35: "cap_wake_alarm",
	36: "cap_block_suspend", 37: "cap_audit_read", 38: "cap_perfmon",
	39: "cap_bpf", 40: "cap_checkpoint_restore",
}

// readFileCaps reads the security.capability xattr and returns a human-readable string.
// Returns empty string if no capabilities are set.
func readFileCaps(path string) string {
	data, err := getXattr(path, "security.capability")
	if err != nil || len(data) < 4 {
		return ""
	}

	// VFS capability header: magic_etc (4 bytes LE)
	// Version in upper byte (VFS_CAP_REVISION_MASK = 0xFF000000)
	// Effective flag in bit 0 (VFS_CAP_FLAGS_EFFECTIVE = 0x000001)
	magicEtc := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	version := magicEtc & 0xFF000000
	effective := magicEtc&0x000001 != 0

	var permitted, inheritable uint64

	switch version {
	case 0x01000000: // VFS_CAP_REVISION_1 — 32-bit caps
		if len(data) < 12 {
			return ""
		}
		permitted = uint64(uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24)
		inheritable = uint64(uint32(data[8]) | uint32(data[9])<<8 | uint32(data[10])<<16 | uint32(data[11])<<24)

	case 0x02000000: // VFS_CAP_REVISION_2/3 — 64-bit caps
		if len(data) < 20 {
			return ""
		}
		permLow := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
		inhLow := uint32(data[8]) | uint32(data[9])<<8 | uint32(data[10])<<16 | uint32(data[11])<<24
		permHigh := uint32(data[12]) | uint32(data[13])<<8 | uint32(data[14])<<16 | uint32(data[15])<<24
		inhHigh := uint32(data[16]) | uint32(data[17])<<8 | uint32(data[18])<<16 | uint32(data[19])<<24
		permitted = uint64(permLow) | uint64(permHigh)<<32
		inheritable = uint64(inhLow) | uint64(inhHigh)<<32

	default:
		return fmt.Sprintf("(unknown cap version 0x%08x)", version)
	}

	if permitted == 0 && inheritable == 0 {
		return ""
	}

	// Format like getcap: "= cap_name1,cap_name2+eip"
	var names []string
	for i := 0; i < len(capNames) && i < 64; i++ {
		if permitted&(1<<i) != 0 {
			if i < len(capNames) && capNames[i] != "" {
				names = append(names, capNames[i])
			} else {
				names = append(names, fmt.Sprintf("cap_%d", i))
			}
		}
	}

	flags := ""
	if effective {
		flags += "e"
	}
	if permitted != 0 {
		flags += "p"
	}
	if inheritable != 0 {
		flags += "i"
	}

	return fmt.Sprintf("= %s+%s", strings.Join(names, ","), flags)
}

// privescCheckSudo enumerates sudo rules for the current user
func privescCheckSudo() structs.CommandResult {
	var sb strings.Builder

	// Try sudo -l (may require password — handle gracefully)
	out, err := execCmdTimeout("sudo", "-n", "-l")
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
		defer structs.ZeroBytes(data) // opsec: clear sudoers rules from memory
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
				structs.ZeroBytes(data) // opsec: clear sudoers.d file contents
			}
		}
		if len(readableFiles) > 0 {
			sb.WriteString(fmt.Sprintf("\n\nReadable /etc/sudoers.d files (%d):\n", len(readableFiles)))
			sb.WriteString(strings.Join(readableFiles, "\n"))
		}
	}

	return successResult(sb.String())
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
		structs.ZeroBytes(data)
		if len(uid0) > 0 {
			sb.WriteString(fmt.Sprintf("\n\n[!] NON-ROOT accounts with UID 0 (%d):\n", len(uid0)))
			sb.WriteString(strings.Join(uid0, "\n"))
		}
	}

	return successResult(sb.String())
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
			structs.ZeroBytes(data)
		}
		containerFound = true
	}

	// Check cgroup for container indicators
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		structs.ZeroBytes(data)
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
			defer structs.ZeroBytes(token) // opsec: clear raw K8s service account token
			// Just show first 40 chars for confirmation
			tokenStr := string(token)
			if len(tokenStr) > 40 {
				tokenStr = tokenStr[:40] + "..."
			}
			sb.WriteString(fmt.Sprintf("  Token: %s\n", tokenStr))
		}
		if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			sb.WriteString(fmt.Sprintf("  Namespace: %s\n", strings.TrimSpace(string(ns))))
			structs.ZeroBytes(ns) // opsec: clear K8s namespace info
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
		structs.ZeroBytes(data)
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
		structs.ZeroBytes(data)
		if strings.Contains(content, "overlay") || strings.Contains(content, "aufs") {
			sb.WriteString("[!] Overlay/AUFS filesystem detected — consistent with container\n")
			containerFound = true
		}
	}

	if !containerFound {
		sb.WriteString("No container indicators found — likely running on bare metal/VM host.\n")
	}

	return successResult(sb.String())
}

// isWritable checks if the current user can write to a path
func isWritable(path string) bool {
	f, err := os.CreateTemp(path, "")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	secureRemove(name)
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

// privescCheckCronScripts checks for cron jobs that reference scripts writable by the current user.
// If a cron job runs as root and calls a script we can write to, we can inject commands.
func privescCheckCronScripts() structs.CommandResult {
	var sb strings.Builder
	var findings []string

	// Parse cron sources for script references
	cronSources := []struct {
		path string
		desc string
	}{
		{"/etc/crontab", "/etc/crontab"},
	}

	// Add /etc/cron.d/ files
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
				cronSources = append(cronSources, struct {
					path string
					desc string
				}{filepath.Join("/etc/cron.d", entry.Name()), "cron.d/" + entry.Name()})
			}
		}
	}

	for _, cs := range cronSources {
		data, err := os.ReadFile(cs.path)
		if err != nil {
			continue
		}
		defer structs.ZeroBytes(data) // opsec: clear cron config (may contain embedded secrets)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Extract potential script paths from cron lines
			scripts := extractScriptPaths(line)
			for _, script := range scripts {
				if isWritable(filepath.Dir(script)) || isWritableFile(script) {
					findings = append(findings, fmt.Sprintf("  [!] %s references writable: %s", cs.desc, script))
				}
			}
		}
	}

	// Check periodic cron directories for writable scripts
	periodicDirs := []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range periodicDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			script := filepath.Join(dir, entry.Name())
			if isWritableFile(script) {
				findings = append(findings, fmt.Sprintf("  [!] Writable cron script: %s", script))
			}
		}
	}

	if len(findings) > 0 {
		sb.WriteString(fmt.Sprintf("[!] Found %d writable cron scripts/targets:\n", len(findings)))
		sb.WriteString(strings.Join(findings, "\n"))
		sb.WriteString("\n[!] Modify these to inject commands that run as the cron job owner (often root)")
	} else {
		sb.WriteString("No writable cron scripts found — cron is not an escalation vector")
	}

	return successResult(sb.String())
}

// extractScriptPaths extracts file paths from a cron line that might be scripts.
func extractScriptPaths(line string) []string {
	var paths []string
	fields := strings.Fields(line)
	// Skip cron timing fields (first 5-6 fields are schedule + optional user)
	for _, field := range fields {
		if strings.HasPrefix(field, "/") && !strings.HasPrefix(field, "/dev/") {
			// Skip output redirection targets
			if strings.Contains(field, ">") {
				continue
			}
			paths = append(paths, field)
		}
	}
	return paths
}

// isWritableFile checks if a specific file can be opened for writing.
func isWritableFile(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// privescCheckNFS checks /etc/exports for NFS shares with no_root_squash.
// no_root_squash allows root on the NFS client to act as root on the server,
// enabling SUID binary deployment for privilege escalation.
func privescCheckNFS() structs.CommandResult {
	var sb strings.Builder

	data, err := os.ReadFile("/etc/exports")
	if err != nil {
		return successResult("No /etc/exports found — NFS is not configured")
	}
	defer structs.ZeroBytes(data)

	var noSquash []string
	var allShares []string

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allShares = append(allShares, "  "+line)
		if strings.Contains(line, "no_root_squash") {
			noSquash = append(noSquash, "  [!] "+line)
		}
	}

	if len(allShares) > 0 {
		sb.WriteString(fmt.Sprintf("NFS exports (%d shares):\n", len(allShares)))
		sb.WriteString(strings.Join(allShares, "\n"))
	}

	if len(noSquash) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n[!] VULNERABLE — %d shares with no_root_squash:\n", len(noSquash)))
		sb.WriteString(strings.Join(noSquash, "\n"))
		sb.WriteString("\n[!] Mount the share, create a SUID binary as root, execute on target for root shell")
	} else if len(allShares) > 0 {
		sb.WriteString("\nAll shares use root_squash (default) — no NFS escalation vector")
	} else {
		sb.WriteString("No NFS exports configured")
	}

	return successResult(sb.String())
}

// privescCheckSystemdUnits checks for systemd service/timer files writable by the current user.
// Writable service files that run as root allow code injection.
func privescCheckSystemdUnits() structs.CommandResult {
	var sb strings.Builder
	var findings []string

	systemdDirs := []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
		"/run/systemd/system",
	}

	for _, dir := range systemdDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
				continue
			}
			path := filepath.Join(dir, name)
			if isWritableFile(path) {
				findings = append(findings, fmt.Sprintf("  [!] Writable: %s", path))
			}
		}
	}

	// Also check user-level systemd directories
	if home := os.Getenv("HOME"); home != "" {
		userDir := filepath.Join(home, ".config/systemd/user")
		if entries, err := os.ReadDir(userDir); err == nil {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".service") || strings.HasSuffix(entry.Name(), ".timer") {
					findings = append(findings, fmt.Sprintf("  [user] %s", filepath.Join(userDir, entry.Name())))
				}
			}
		}
	}

	if len(findings) > 0 {
		sb.WriteString(fmt.Sprintf("[!] Found %d writable/user systemd units:\n", len(findings)))
		sb.WriteString(strings.Join(findings, "\n"))
		sb.WriteString("\n[!] Modify ExecStart= to inject commands that run as the service user")
	} else {
		sb.WriteString("No writable systemd units found — systemd is not an escalation vector")
	}

	return successResult(sb.String())
}

// privescCheckSudoToken checks for sudo credential caching that could be reused via ptrace.
// If another process from the same user recently ran sudo, the timestamp file may allow
// sudo without a password (within timeout, typically 15 minutes).
func privescCheckSudoToken() structs.CommandResult {
	var sb strings.Builder

	// Check /var/run/sudo/ts/<username> or /var/db/sudo/ts/<username>
	tsLocations := []string{"/var/run/sudo/ts", "/var/db/sudo/ts", "/run/sudo/ts"}

	username := ""
	if u, err := os.UserHomeDir(); err == nil {
		_ = u
	}
	if cu, err := os.Hostname(); err == nil {
		_ = cu
	}
	// Get actual username
	if uStr := os.Getenv("USER"); uStr != "" {
		username = uStr
	}

	found := false
	for _, tsDir := range tsLocations {
		if _, err := os.Stat(tsDir); err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("Sudo timestamp directory exists: %s\n", tsDir))

		if username != "" {
			tsFile := filepath.Join(tsDir, username)
			if info, err := os.Stat(tsFile); err == nil {
				sb.WriteString(fmt.Sprintf("[!] Sudo timestamp file found: %s\n", tsFile))
				sb.WriteString(fmt.Sprintf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05")))
				sb.WriteString("  [!] If within sudo timeout (default 15min), sudo may work without password\n")
				sb.WriteString("  [!] Also exploitable via ptrace on processes from the same tty/session\n")
				found = true
			}
		}

		// List all timestamp files
		entries, err := os.ReadDir(tsDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  Timestamp: %s (modified: %s)\n",
				entry.Name(), info.ModTime().Format("2006-01-02 15:04:05")))
		}
		found = true
	}

	// Check if ptrace is restricted
	if data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		scope := strings.TrimSpace(string(data))
		structs.ZeroBytes(data)
		sb.WriteString(fmt.Sprintf("\nptrace_scope: %s", scope))
		switch scope {
		case "0":
			sb.WriteString(" (classic — any process can ptrace, sudo token reuse possible)")
		case "1":
			sb.WriteString(" (restricted — only parent can ptrace, limits sudo token attack)")
		case "2":
			sb.WriteString(" (admin only — ptrace requires CAP_SYS_PTRACE)")
		case "3":
			sb.WriteString(" (disabled — ptrace completely blocked)")
		}
		sb.WriteString("\n")
	}

	if !found {
		sb.WriteString("No sudo timestamp files found — sudo token reuse not available")
	}

	return successResult(sb.String())
}

// privescCheckPathHijack checks for writable directories in PATH that appear
// before system directories, enabling command hijacking for privilege escalation.
func privescCheckPathHijack() structs.CommandResult {
	var sb strings.Builder

	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		sb.WriteString("PATH is empty — no hijack analysis possible")
		return successResult(sb.String())
	}

	dirs := strings.Split(pathEnv, ":")
	systemDirs := map[string]bool{
		"/usr/bin": true, "/usr/sbin": true, "/bin": true, "/sbin": true,
		"/usr/local/bin": true, "/usr/local/sbin": true,
	}

	results := analyzePathHijack(dirs, systemDirs)

	if len(results) == 0 {
		sb.WriteString("No PATH hijacking opportunities found")
		return successResult(sb.String())
	}

	sb.WriteString(fmt.Sprintf("Found %d PATH hijacking opportunities:\n\n", len(results)))
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("  [!] %s (position %d, before %s)\n", r.Dir, r.Position, r.BeforeSystem))
		sb.WriteString(fmt.Sprintf("      Writable: %v | Owner: %s | Mode: %s\n", r.Writable, r.Owner, r.Mode))
		if r.Writable {
			sb.WriteString("      → Place a malicious binary here to hijack commands\n")
		}
	}

	return successResult(sb.String())
}

// pathHijackResult represents a single PATH hijacking opportunity.
type pathHijackResult struct {
	Dir          string
	Position     int
	BeforeSystem string
	Writable     bool
	Owner        string
	Mode         string
}

// analyzePathHijack inspects PATH directories for hijacking opportunities.
// A directory is a hijack candidate if it's writable and appears before a system directory.
func analyzePathHijack(dirs []string, systemDirs map[string]bool) []pathHijackResult {
	var results []pathHijackResult

	// Find first system directory position
	firstSystem := -1
	firstSystemDir := ""
	for i, d := range dirs {
		if systemDirs[d] {
			firstSystem = i
			firstSystemDir = d
			break
		}
	}

	for i, d := range dirs {
		if d == "" || d == "." {
			// Current directory or empty entry — always a hijack risk
			results = append(results, pathHijackResult{
				Dir:          fmt.Sprintf("%q (relative)", d),
				Position:     i + 1,
				BeforeSystem: firstSystemDir,
				Writable:     true,
				Owner:        "n/a",
				Mode:         "n/a",
			})
			continue
		}

		if systemDirs[d] {
			continue // Skip system dirs themselves
		}

		// Only report dirs that appear before a system directory
		if firstSystem >= 0 && i >= firstSystem {
			continue
		}

		info, err := os.Stat(d)
		if err != nil {
			continue // Dir doesn't exist
		}

		writable := isDirWritable(d)
		ownerStr, groupStr := getFileOwner(d)
		owner := ownerStr + ":" + groupStr
		mode := info.Mode().Perm().String()

		results = append(results, pathHijackResult{
			Dir:          d,
			Position:     i + 1,
			BeforeSystem: firstSystemDir,
			Writable:     writable,
			Owner:        owner,
			Mode:         mode,
		})
	}

	return results
}

// privescCheckDockerGroup checks if the current user is in the docker group,
// which allows trivial root escalation via container escape.
func privescCheckDockerGroup() structs.CommandResult {
	var sb strings.Builder

	groups := parseDockerGroupMembership()

	if groups.inDocker {
		sb.WriteString("[!] CRITICAL: Current user is in the 'docker' group\n")
		sb.WriteString("    → Can escalate to root via: docker run -v /:/mnt --rm -it alpine chroot /mnt sh\n")
		sb.WriteString("    → Or mount /etc/shadow, /etc/passwd, /root/.ssh, etc.\n")
	}

	if groups.inLxd {
		sb.WriteString("[!] CRITICAL: Current user is in the 'lxd' group\n")
		sb.WriteString("    → Can escalate to root via LXD container with host filesystem mount\n")
	}

	if groups.inPodman {
		sb.WriteString("[!] WARNING: Current user has rootless podman access\n")
		sb.WriteString("    → May be able to escalate via user namespace manipulation\n")
	}

	if groups.dockerSocket {
		sb.WriteString("[!] Docker socket is accessible at /var/run/docker.sock\n")
		sb.WriteString("    → Direct API access enables root escalation even without group membership\n")
	}

	if !groups.inDocker && !groups.inLxd && !groups.inPodman && !groups.dockerSocket {
		sb.WriteString("Not in docker/lxd/podman groups, no docker socket access")
	}

	return successResult(sb.String())
}

// dockerGroupInfo holds the results of docker/container group membership checks.
type dockerGroupInfo struct {
	inDocker     bool
	inLxd        bool
	inPodman     bool
	dockerSocket bool
}

// parseDockerGroupMembership checks group membership and socket access.
func parseDockerGroupMembership() dockerGroupInfo {
	var info dockerGroupInfo

	// Read current user's groups from /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		groups := parseGroupsFromStatus(string(data))
		structs.ZeroBytes(data)
		groupNames := resolveGroupNames(groups)

		for _, name := range groupNames {
			switch name {
			case "docker":
				info.inDocker = true
			case "lxd":
				info.inLxd = true
			case "podman":
				info.inPodman = true
			}
		}
	}

	// Check docker socket accessibility
	if fi, err := os.Stat("/var/run/docker.sock"); err == nil {
		// Check if we can actually connect (socket exists and is accessible)
		if fi.Mode()&os.ModeSocket != 0 {
			info.dockerSocket = true
		}
	}

	return info
}

// parseGroupsFromStatus extracts group IDs from /proc/self/status content.
func parseGroupsFromStatus(content string) []string {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "Groups:") {
			parts := strings.Fields(strings.TrimPrefix(line, "Groups:"))
			return parts
		}
	}
	return nil
}

// resolveGroupNames maps group IDs to names using /etc/group.
func resolveGroupNames(gids []string) []string {
	if len(gids) == 0 {
		return nil
	}

	gidSet := make(map[string]bool)
	for _, g := range gids {
		gidSet[g] = true
	}

	f, err := os.Open("/etc/group")
	if err != nil {
		return nil
	}
	defer f.Close()

	var names []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 4)
		if len(parts) >= 3 && gidSet[parts[2]] {
			names = append(names, parts[0])
		}
	}
	return names
}

// dangerousGroup describes a group that grants elevated privileges.
type dangerousGroup struct {
	Name   string
	Risk   string
	Impact string
}

// dangerousGroups lists Linux groups that grant elevated access beyond normal users.
// docker/lxd/podman are excluded since they're covered by the docker-group action.
var dangerousGroups = []dangerousGroup{
	{"disk", "CRITICAL", "Raw disk device access (/dev/sd*) — read entire filesystem including /etc/shadow"},
	{"shadow", "CRITICAL", "Read /etc/shadow — extract password hashes for offline cracking"},
	{"sudo", "HIGH", "Sudo access (may require password)"},
	{"wheel", "HIGH", "Sudo access (may require password, common on RHEL/Fedora)"},
	{"adm", "MEDIUM", "Read /var/log/* — access system logs, may contain credentials/tokens"},
	{"staff", "MEDIUM", "Write to /usr/local — binary hijacking in PATH"},
	{"root", "CRITICAL", "Root group membership — may grant access to root-owned files"},
	{"video", "LOW", "Framebuffer/video device access — keylogger via /dev/fb0, screen capture"},
	{"kvm", "MEDIUM", "KVM virtual machine management — VM escape, credential extraction"},
	{"dialout", "MEDIUM", "Serial port access (/dev/ttyS*) — potential OT/SCADA interaction"},
	{"tape", "LOW", "Tape device access — read backup media"},
	{"cdrom", "LOW", "CD/DVD device access"},
	{"plugdev", "LOW", "USB/removable device access"},
	{"render", "LOW", "GPU compute access — may enable GPU-based hash cracking"},
	{"lpadmin", "LOW", "CUPS printer admin — potential lateral movement via printer exploitation"},
	{"bluetooth", "LOW", "Bluetooth device access"},
	{"netdev", "MEDIUM", "Network device management — interface manipulation"},
	{"wireshark", "MEDIUM", "Packet capture — network credential sniffing"},
}

// privescCheckDangerousGroups checks the current user's group memberships for
// groups that grant elevated or unusual access. Complements docker-group check.
func privescCheckDangerousGroups() structs.CommandResult {
	var sb strings.Builder

	// Get current user's groups
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return errorf("Cannot read /proc/self/status: %v", err)
	}
	gids := parseGroupsFromStatus(string(data))
	structs.ZeroBytes(data)
	groupNames := resolveGroupNames(gids)

	nameSet := make(map[string]bool)
	for _, n := range groupNames {
		nameSet[n] = true
	}

	var critical, high, medium, low []string
	for _, dg := range dangerousGroups {
		if nameSet[dg.Name] {
			entry := fmt.Sprintf("  [%s] %s — %s", dg.Risk, dg.Name, dg.Impact)
			switch dg.Risk {
			case "CRITICAL":
				critical = append(critical, entry)
			case "HIGH":
				high = append(high, entry)
			case "MEDIUM":
				medium = append(medium, entry)
			default:
				low = append(low, entry)
			}
		}
	}

	total := len(critical) + len(high) + len(medium) + len(low)
	sb.WriteString(fmt.Sprintf("Current user groups: %s\n", strings.Join(groupNames, ", ")))
	sb.WriteString(fmt.Sprintf("Dangerous group memberships (%d found):\n", total))

	if total == 0 {
		sb.WriteString("  (none — user is in standard groups only)")
		return successResult(sb.String())
	}

	if len(critical) > 0 {
		sb.WriteString("\n[!!] CRITICAL:\n")
		sb.WriteString(strings.Join(critical, "\n"))
		sb.WriteString("\n")
	}
	if len(high) > 0 {
		sb.WriteString("\n[!] HIGH:\n")
		sb.WriteString(strings.Join(high, "\n"))
		sb.WriteString("\n")
	}
	if len(medium) > 0 {
		sb.WriteString("\nMEDIUM:\n")
		sb.WriteString(strings.Join(medium, "\n"))
		sb.WriteString("\n")
	}
	if len(low) > 0 {
		sb.WriteString("\nLOW:\n")
		sb.WriteString(strings.Join(low, "\n"))
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}

// privescCheckPolkit enumerates Polkit rules and policies that may allow
// unprivileged users to perform privileged operations without authentication.
func privescCheckPolkit() structs.CommandResult {
	var sb strings.Builder

	// Check if pkexec has SUID (common privesc vector — CVE-2021-4034)
	if info, err := os.Stat("/usr/bin/pkexec"); err == nil {
		if info.Mode()&os.ModeSetuid != 0 {
			sb.WriteString("[!] /usr/bin/pkexec is SUID — potential CVE-2021-4034 (PwnKit) if unpatched\n")
		}
	}

	// Check Polkit version via polkitd
	if data, err := os.ReadFile("/usr/lib/polkit-1/polkitd"); err == nil {
		structs.ZeroBytes(data)
		sb.WriteString("polkitd binary exists at /usr/lib/polkit-1/polkitd\n")
	} else if data, err := os.ReadFile("/usr/libexec/polkitd"); err == nil {
		structs.ZeroBytes(data)
		sb.WriteString("polkitd binary exists at /usr/libexec/polkitd\n")
	}

	// Scan JavaScript rules in /etc/polkit-1/rules.d/ and /usr/share/polkit-1/rules.d/
	rulesDirs := []string{
		"/etc/polkit-1/rules.d",
		"/usr/share/polkit-1/rules.d",
	}
	var jsRules []string
	for _, dir := range rulesDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rules") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := string(data)
			structs.ZeroBytes(data)

			// Flag rules that return YES (allow without password)
			interesting := strings.Contains(content, "return polkit.Result.YES") ||
				strings.Contains(content, "YES")
			writable := isWritableFile(path)

			status := ""
			if interesting {
				status = " [!] ALLOWS WITHOUT AUTH"
			}
			if writable {
				status += " [!] WRITABLE"
			}
			jsRules = append(jsRules, fmt.Sprintf("  %s%s", path, status))
		}
	}

	if len(jsRules) > 0 {
		sb.WriteString(fmt.Sprintf("\nPolkit JS rules (%d):\n", len(jsRules)))
		sb.WriteString(strings.Join(jsRules, "\n"))
		sb.WriteString("\n")
	}

	// Scan legacy .pkla files in /etc/polkit-1/localauthority/
	pklaDir := "/etc/polkit-1/localauthority"
	var pklaFiles []string
	_ = filepath.WalkDir(pklaDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".pkla") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			pklaFiles = append(pklaFiles, fmt.Sprintf("  %s (unreadable)", path))
			return nil
		}
		content := string(data)
		structs.ZeroBytes(data)

		interesting := strings.Contains(content, "ResultAny=yes") ||
			strings.Contains(content, "ResultInactive=yes") ||
			strings.Contains(content, "ResultActive=yes")
		writable := isWritableFile(path)

		status := ""
		if interesting {
			status = " [!] GRANTS ACCESS"
		}
		if writable {
			status += " [!] WRITABLE"
		}
		pklaFiles = append(pklaFiles, fmt.Sprintf("  %s%s", path, status))
		return nil
	})

	if len(pklaFiles) > 0 {
		sb.WriteString(fmt.Sprintf("\nPolkit legacy .pkla files (%d):\n", len(pklaFiles)))
		sb.WriteString(strings.Join(pklaFiles, "\n"))
		sb.WriteString("\n")
	}

	// Scan Polkit action definitions for interesting actions
	actionsDir := "/usr/share/polkit-1/actions"
	var interestingActions []string
	if entries, err := os.ReadDir(actionsDir); err == nil {
		// Only check for writable action files (not parsing XML — too noisy)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".policy") {
				continue
			}
			path := filepath.Join(actionsDir, entry.Name())
			if isWritableFile(path) {
				interestingActions = append(interestingActions,
					fmt.Sprintf("  [!] WRITABLE policy: %s", path))
			}
		}
	}

	if len(interestingActions) > 0 {
		sb.WriteString(fmt.Sprintf("\nWritable Polkit action policies (%d):\n", len(interestingActions)))
		sb.WriteString(strings.Join(interestingActions, "\n"))
		sb.WriteString("\n")
	}

	// Check if rules directories are writable (drop a rule → instant privesc)
	for _, dir := range rulesDirs {
		if isDirWritable(dir) {
			sb.WriteString(fmt.Sprintf("\n[!!] CRITICAL: %s is WRITABLE — drop a .rules file for instant root\n", dir))
		}
	}

	if len(jsRules) == 0 && len(pklaFiles) == 0 && len(interestingActions) == 0 {
		sb.WriteString("\nNo custom Polkit rules or writable policies found")
	}

	return successResult(sb.String())
}

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
