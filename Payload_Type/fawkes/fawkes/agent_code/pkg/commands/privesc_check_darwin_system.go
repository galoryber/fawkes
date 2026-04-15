//go:build darwin

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

// macPrivescCheckSIP checks System Integrity Protection status
func macPrivescCheckSIP() structs.CommandResult {
	var sb strings.Builder

	out, err := execCmdTimeout("csrutil", "status")
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
	out, err = execCmdTimeout("csrutil", "authenticated-root", "status")
	if err == nil {
		output := strings.TrimSpace(string(out))
		if output != "" {
			sb.WriteString(output + "\n")
		}
	}

	return successResult(sb.String())
}

// macPrivescCheckSUID finds SUID and SGID binaries
func macPrivescCheckSUID() structs.CommandResult {
	var sb strings.Builder
	var suidFiles []string
	var sgidFiles []string

	searchPaths := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"/bin", "/sbin", "/opt/homebrew/bin", "/opt/local/bin"}

	for _, searchPath := range searchPaths {
		_ = filepath.WalkDir(searchPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
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

	// Flag interesting SUID binaries
	interestingBins := []string{"nmap", "vim", "vi", "nano", "find", "bash", "sh", "zsh",
		"env", "python", "python3", "perl", "ruby", "node", "lua", "awk",
		"less", "more", "ftp", "socat", "nc", "ncat", "wget", "curl",
		"gcc", "make", "docker", "mount", "umount", "screen", "tmux",
		"cp", "mv", "dd", "tee", "rsync", "tar", "zip", "unzip",
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

// macPrivescCheckSudo checks sudo rules
func macPrivescCheckSudo() structs.CommandResult {
	var sb strings.Builder

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

	// Check group memberships that grant admin (native, no child process)
	idOutput := nativeIDString()
	sb.WriteString(fmt.Sprintf("\nCurrent identity: %s\n", idOutput))
	if strings.Contains(idOutput, "(admin)") || strings.Contains(idOutput, "(wheel)") {
		sb.WriteString("[*] User is in admin/wheel group — may have sudo access with password\n")
	}

	return successResult(sb.String())
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

	return successResult(sb.String())
}
