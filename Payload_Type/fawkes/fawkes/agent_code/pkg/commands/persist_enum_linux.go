//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// PersistEnumCommand enumerates Linux persistence mechanisms.
type PersistEnumCommand struct{}

func (c *PersistEnumCommand) Name() string { return "persist-enum" }
func (c *PersistEnumCommand) Description() string {
	return "Enumerate Linux persistence mechanisms — cron, systemd, shell profiles, SSH keys, init scripts, udev rules, kernel modules, motd, at jobs (T1547/T1546)"
}

func (c *PersistEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args persistEnumArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}
	if args.Category == "" {
		args.Category = "all"
	}

	var sb strings.Builder
	sb.WriteString("=== Persistence Enumeration (Linux) ===\n\n")

	cat := strings.ToLower(args.Category)
	found := 0

	if cat == "all" || cat == "cron" {
		found += persistEnumCron(&sb)
	}
	if cat == "all" || cat == "systemd" {
		found += persistEnumSystemd(&sb)
	}
	if cat == "all" || cat == "shell" {
		found += persistEnumShellProfiles(&sb)
	}
	if cat == "all" || cat == "startup" {
		found += persistEnumStartup(&sb)
	}
	if cat == "all" || cat == "ssh" {
		found += persistEnumSSHKeys(&sb)
	}
	if cat == "all" || cat == "preload" {
		found += persistEnumPreload(&sb)
	}
	if cat == "all" || cat == "udev" {
		found += persistEnumUdev(&sb)
	}
	if cat == "all" || cat == "modules" {
		found += persistEnumKernelModules(&sb)
	}
	if cat == "all" || cat == "motd" {
		found += persistEnumMotd(&sb)
	}
	if cat == "all" || cat == "at" {
		found += persistEnumAtJobs(&sb)
	}

	sb.WriteString(fmt.Sprintf("\n=== Total: %d persistence items found ===\n", found))

	return successResult(sb.String())
}

// persistEnumCron checks system and user crontabs.
func persistEnumCron(sb *strings.Builder) int {
	sb.WriteString("--- Cron Jobs ---\n")
	count := 0

	// System crontab
	if content, err := os.ReadFile("/etc/crontab"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [/etc/crontab] %s\n", line))
			count++
		}
	}

	// /etc/cron.d/ directory
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join("/etc/cron.d", entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				sb.WriteString(fmt.Sprintf("  [%s] %s\n", path, line))
				count++
			}
		}
	}

	// User crontabs in /var/spool/cron/crontabs/
	cronDirs := []string{"/var/spool/cron/crontabs", "/var/spool/cron"}
	for _, cronDir := range cronDirs {
		entries, err := os.ReadDir(cronDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(cronDir, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				sb.WriteString(fmt.Sprintf("  [%s:%s] %s\n", entry.Name(), cronDir, line))
				count++
			}
		}
	}

	// Periodic cron directories
	periodicDirs := []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range periodicDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", dir, entry.Name()))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumSystemd checks for non-default systemd services and timers.
func persistEnumSystemd(sb *strings.Builder) int {
	sb.WriteString("--- Systemd Units ---\n")
	count := 0

	// User and system unit directories
	homeDir := currentHomeDir()
	unitDirs := []struct {
		path string
		desc string
	}{
		{"/etc/systemd/system", "system"},
		{filepath.Join(homeDir, ".config/systemd/user"), "user"},
	}

	for _, ud := range unitDirs {
		entries, err := os.ReadDir(ud.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			// Skip default targets, wants directories, and symlinks to /dev/null (masked)
			if entry.IsDir() || name == "default.target" {
				continue
			}
			// Only show .service and .timer files
			if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [%s] %s\n", ud.desc, name))
				count++
				continue
			}

			// Check if it's a symlink (enabled unit)
			detail := ""
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(filepath.Join(ud.path, name))
				if err == nil {
					detail = fmt.Sprintf(" → %s", target)
				}
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s%s\n", ud.desc, name, detail))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumShellProfiles checks shell configuration files for modifications.
func persistEnumShellProfiles(sb *strings.Builder) int {
	sb.WriteString("--- Shell Profiles ---\n")
	count := 0

	homeDir := currentHomeDir()

	// System-wide profiles
	systemProfiles := []string{"/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"}
	for _, path := range systemProfiles {
		if info, err := os.Stat(path); err == nil {
			sb.WriteString(fmt.Sprintf("  %s (modified: %s, size: %d)\n", path, info.ModTime().Format("2006-01-02 15:04"), info.Size()))
			count++
		}
	}

	// /etc/profile.d/ scripts
	if entries, err := os.ReadDir("/etc/profile.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  /etc/profile.d/%s\n", entry.Name()))
			count++
		}
	}

	// User profiles
	userProfiles := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv", ".zprofile"}
	for _, name := range userProfiles {
		path := filepath.Join(homeDir, name)
		if info, err := os.Stat(path); err == nil {
			sb.WriteString(fmt.Sprintf("  %s (modified: %s, size: %d)\n", path, info.ModTime().Format("2006-01-02 15:04"), info.Size()))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumStartup checks init.d scripts, rc.local, and XDG autostart.
func persistEnumStartup(sb *strings.Builder) int {
	sb.WriteString("--- Startup / Init ---\n")
	count := 0

	// rc.local
	if content, err := os.ReadFile("/etc/rc.local"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || line == "exit 0" {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [rc.local] %s\n", line))
			count++
		}
	}

	// /etc/init.d/ non-default scripts
	if entries, err := os.ReadDir("/etc/init.d"); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || strings.HasPrefix(name, ".") || name == "README" {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [init.d] %s\n", name))
			count++
		}
	}

	// XDG autostart entries
	homeDir := currentHomeDir()
	autostartDirs := []string{
		filepath.Join(homeDir, ".config/autostart"),
		"/etc/xdg/autostart",
	}
	for _, dir := range autostartDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".desktop") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", dir, entry.Name()))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumSSHKeys checks for SSH authorized_keys files.
func persistEnumSSHKeys(sb *strings.Builder) int {
	sb.WriteString("--- SSH Authorized Keys ---\n")
	count := 0

	homeDir := currentHomeDir()
	authKeysPath := filepath.Join(homeDir, ".ssh/authorized_keys")

	if content, err := os.ReadFile(authKeysPath); err == nil {
		lines := strings.Split(string(content), "\n")
		structs.ZeroBytes(content) // opsec: clear SSH authorized_keys data
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Truncate long key data, show type and comment
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				sb.WriteString(fmt.Sprintf("  %s %s...%s %s\n", parts[0], parts[1][:min(20, len(parts[1]))], parts[1][max(0, len(parts[1])-8):], parts[2]))
			} else if len(parts) >= 2 {
				sb.WriteString(fmt.Sprintf("  %s %s...%s\n", parts[0], parts[1][:min(20, len(parts[1]))], parts[1][max(0, len(parts[1])-8):]))
			} else {
				sb.WriteString(fmt.Sprintf("  %s\n", line[:min(80, len(line))]))
			}
			count++
		}
	}

	// Also check /root/.ssh/authorized_keys if accessible
	if homeDir != "/root" {
		rootAuthKeys := "/root/.ssh/authorized_keys"
		if content, err := os.ReadFile(rootAuthKeys); err == nil {
			rootLines := strings.Split(string(content), "\n")
			structs.ZeroBytes(content) // opsec: clear SSH authorized_keys data
			for _, line := range rootLines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					sb.WriteString(fmt.Sprintf("  [root] %s %s...%s %s\n", parts[0], parts[1][:min(20, len(parts[1]))], parts[1][max(0, len(parts[1])-8):], parts[2]))
				} else {
					sb.WriteString(fmt.Sprintf("  [root] %s\n", line[:min(80, len(line))]))
				}
				count++
			}
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}

	// SSH private keys — indicate key-based auth capability
	keyFiles := []string{"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}
	sshDir := filepath.Join(homeDir, ".ssh")
	for _, name := range keyFiles {
		keyPath := filepath.Join(sshDir, name)
		info, err := os.Stat(keyPath)
		if err != nil {
			continue
		}
		encrypted := "plaintext"
		if content, err := os.ReadFile(keyPath); err == nil {
			if strings.Contains(string(content), "ENCRYPTED") {
				encrypted = "encrypted"
			}
			structs.ZeroBytes(content)
		}
		sb.WriteString(fmt.Sprintf("  [private key] %s (%d bytes, %s)\n", name, info.Size(), encrypted))
		count++
	}

	// SSH agent sockets — hijackable for lateral movement
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		sb.WriteString(fmt.Sprintf("  [agent socket] SSH_AUTH_SOCK=%s\n", sock))
		count++
	}
	// Scan /tmp/ssh-* for agent sockets from other sessions
	if entries, err := filepath.Glob("/tmp/ssh-*/agent.*"); err == nil {
		for _, entry := range entries {
			info, err := os.Stat(entry)
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSocket != 0 {
				sb.WriteString(fmt.Sprintf("  [agent socket] %s\n", entry))
				count++
			}
		}
	}

	sb.WriteString("\n")
	return count
}

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

// persistEnumMotd checks for MOTD (Message of the Day) scripts that run on login (T1546).
func persistEnumMotd(sb *strings.Builder) int {
	sb.WriteString("--- MOTD Scripts ---\n")
	count := 0

	motdDirs := []string{"/etc/update-motd.d", "/etc/profile.d"}

	for _, dir := range motdDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			// For /etc/profile.d only show .sh files (they're sourced on login)
			if dir == "/etc/profile.d" && !strings.HasSuffix(entry.Name(), ".sh") {
				continue
			}
			// For update-motd.d, skip if already counted in startup check
			if dir == "/etc/update-motd.d" {
				info, err := entry.Info()
				if err != nil {
					continue
				}
				mode := info.Mode()
				if mode&0111 == 0 {
					continue // Not executable
				}
				sb.WriteString(fmt.Sprintf("  [%s] %s (%s)\n", dir, entry.Name(), mode.String()))
				count++
			}
		}
	}

	// Also check /etc/motd for static MOTD
	if info, err := os.Stat("/etc/motd"); err == nil && info.Size() > 0 {
		sb.WriteString(fmt.Sprintf("  [/etc/motd] static message (%d bytes)\n", info.Size()))
		count++
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumAtJobs checks for scheduled at jobs (one-time execution).
func persistEnumAtJobs(sb *strings.Builder) int {
	sb.WriteString("--- At Jobs ---\n")
	count := 0

	atDirs := []string{"/var/spool/at", "/var/spool/atjobs"}

	for _, dir := range atDirs {
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
				continue
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s (%d bytes, modified: %s)\n",
				dir, entry.Name(), info.Size(), info.ModTime().Format("2006-01-02 15:04")))
			count++
		}
	}

	// Check /etc/at.allow and /etc/at.deny for access control
	if _, err := os.Stat("/etc/at.allow"); err == nil {
		sb.WriteString("  [access] /etc/at.allow exists (only listed users can use at)\n")
	} else if _, err := os.Stat("/etc/at.deny"); err == nil {
		sb.WriteString("  [access] /etc/at.deny exists (listed users denied at)\n")
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

func currentHomeDir() string {
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return "/root"
}
