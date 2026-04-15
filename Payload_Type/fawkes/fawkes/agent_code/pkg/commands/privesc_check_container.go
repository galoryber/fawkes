//go:build linux

package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

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
