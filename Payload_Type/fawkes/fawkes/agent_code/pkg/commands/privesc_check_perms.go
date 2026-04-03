//go:build linux

package commands

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

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
