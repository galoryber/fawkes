//go:build !windows
// +build !windows

package commands

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

type WhoamiCommand struct{}

func (c *WhoamiCommand) Name() string {
	return "whoami"
}

func (c *WhoamiCommand) Description() string {
	return "Display current user identity and security context"
}

func (c *WhoamiCommand) Execute(task structs.Task) structs.CommandResult {
	var lines []string

	u, err := user.Current()
	if err != nil {
		return errorf("Failed to get current user: %v", err)
	}

	// Hostname
	if hostname, err := os.Hostname(); err == nil {
		lines = append(lines, fmt.Sprintf("Host:     %s", hostname))
	}

	lines = append(lines, fmt.Sprintf("User:     %s", u.Username))
	lines = append(lines, fmt.Sprintf("UID:      %s", u.Uid))
	lines = append(lines, fmt.Sprintf("GID:      %s", u.Gid))
	if u.HomeDir != "" {
		lines = append(lines, fmt.Sprintf("Home:     %s", u.HomeDir))
	}

	// Check for root
	if u.Uid == "0" {
		lines = append(lines, "Privilege: root")
	}

	// Effective vs real UID (detect suid)
	euid := os.Geteuid()
	ruid := os.Getuid()
	if euid != ruid {
		lines = append(lines, fmt.Sprintf("EUID:     %d (differs from UID — possible SUID)", euid))
	}

	// Supplementary groups
	gids, err := os.Getgroups()
	if err == nil && len(gids) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Groups:")
		for _, gid := range gids {
			g, gErr := user.LookupGroupId(strconv.Itoa(gid))
			if gErr == nil {
				lines = append(lines, fmt.Sprintf("  %s (gid=%d)", g.Name, gid))
			} else {
				lines = append(lines, fmt.Sprintf("  gid=%d", gid))
			}
		}
	}

	// Platform-specific security context
	if runtime.GOOS == "linux" {
		lines = append(lines, whoamiLinuxContext()...)
	}

	return successResult(strings.Join(lines, "\n"))
}

// whoamiLinuxContext gathers Linux-specific security context: capabilities,
// SELinux/AppArmor labels, and container detection.
func whoamiLinuxContext() []string {
	var lines []string

	// Process capabilities from /proc/self/status
	capEff, capPrm := readLinuxCapabilities()
	if capEff != "" {
		lines = append(lines, "")
		if isFullCapabilities(capEff) {
			lines = append(lines, "Capabilities: FULL (all capabilities — root-equivalent)")
		} else {
			caps := parseLinuxCapabilities(capEff)
			if len(caps) == 0 {
				lines = append(lines, "Capabilities: none")
			} else {
				lines = append(lines, fmt.Sprintf("Effective Capabilities (%d):", len(caps)))
				for _, cap := range caps {
					lines = append(lines, "  "+cap)
				}
			}
		}
		// Note if permitted differs from effective
		if capPrm != "" && capPrm != capEff {
			prmCaps := parseLinuxCapabilities(capPrm)
			effCaps := parseLinuxCapabilities(capEff)
			if len(prmCaps) > len(effCaps) {
				lines = append(lines, fmt.Sprintf("  [!] %d additional permitted capabilities available", len(prmCaps)-len(effCaps)))
			}
		}
	}

	// SELinux context
	if data, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		label := strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
		if label != "" && label != "unconfined" {
			lines = append(lines, "")
			lines = append(lines, fmt.Sprintf("SELinux:  %s", label))
		}
	}

	// AppArmor profile
	if data, err := os.ReadFile("/proc/self/attr/apparmor/current"); err == nil {
		profile := strings.TrimSpace(string(data))
		if profile != "" && profile != "unconfined" {
			lines = append(lines, fmt.Sprintf("AppArmor: %s", profile))
		}
	}

	// Container detection
	if container := detectContainer(); container != "" {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("Container: %s", container))
	}

	return lines
}

// readLinuxCapabilities reads CapEff and CapPrm from /proc/self/status.
func readLinuxCapabilities() (capEff, capPrm string) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "CapEff:") {
			capEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		} else if strings.HasPrefix(line, "CapPrm:") {
			capPrm = strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
		}
	}
	return
}

// detectContainer checks if the process is running inside a container.
func detectContainer() string {
	// Check /.dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "Docker"
	}

	// Check /proc/1/cgroup for container indicators
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		switch {
		case strings.Contains(content, "docker"):
			return "Docker"
		case strings.Contains(content, "kubepods"):
			return "Kubernetes"
		case strings.Contains(content, "lxc"):
			return "LXC"
		}
	}

	// Check for container environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "Kubernetes"
	}
	if os.Getenv("container") != "" {
		return os.Getenv("container")
	}

	return ""
}
