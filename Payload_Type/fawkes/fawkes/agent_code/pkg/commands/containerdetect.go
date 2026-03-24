package commands

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// ContainerDetectCommand detects container and virtualization environments.
type ContainerDetectCommand struct{}

func (c *ContainerDetectCommand) Name() string { return "container-detect" }
func (c *ContainerDetectCommand) Description() string {
	return "Detect container runtime and environment type"
}

type containerEvidence struct {
	Check   string
	Result  string
	Details string
}

func (c *ContainerDetectCommand) Execute(task structs.Task) structs.CommandResult {
	var evidence []containerEvidence
	var detected string

	switch runtime.GOOS {
	case "linux":
		evidence, detected = containerDetectLinux()
	case "darwin":
		evidence, detected = containerDetectDarwin()
	default:
		evidence, detected = containerDetectWindows()
	}

	var sb strings.Builder
	sb.WriteString("[*] Container/Environment Detection\n\n")

	if detected != "none" {
		sb.WriteString(fmt.Sprintf("  Environment: %s\n\n", detected))
	} else {
		sb.WriteString("  Environment: bare metal / VM (no container detected)\n\n")
	}

	sb.WriteString(fmt.Sprintf("%-35s %-12s %s\n", "Check", "Result", "Details"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, e := range evidence {
		sb.WriteString(fmt.Sprintf("%-35s %-12s %s\n", e.Check, e.Result, e.Details))
	}

	return successResult(sb.String())
}

func containerDetectLinux() ([]containerEvidence, string) {
	var evidence []containerEvidence
	detected := "none"

	// Check /.dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		evidence = append(evidence, containerEvidence{"/.dockerenv", "FOUND", "Docker container indicator"})
		detected = "Docker"
	} else {
		evidence = append(evidence, containerEvidence{"/.dockerenv", "absent", ""})
	}

	// Check /run/.containerenv (Podman)
	if data, err := os.ReadFile("/run/.containerenv"); err == nil {
		details := "Podman container indicator"
		if len(data) > 0 {
			lines := strings.SplitN(string(data), "\n", 5)
			if len(lines) > 0 {
				details = strings.Join(lines, "; ")
				if len(details) > 100 {
					details = details[:100] + "..."
				}
			}
		}
		structs.ZeroBytes(data) // opsec
		evidence = append(evidence, containerEvidence{"/run/.containerenv", "FOUND", details})
		if detected == "none" {
			detected = "Podman"
		}
	} else {
		evidence = append(evidence, containerEvidence{"/run/.containerenv", "absent", ""})
	}

	// Check cgroup for container indicators
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		structs.ZeroBytes(data) // opsec: cgroup paths may reveal infrastructure
		if strings.Contains(content, "docker") {
			evidence = append(evidence, containerEvidence{"/proc/1/cgroup", "DOCKER", "docker found in cgroup"})
			if detected == "none" {
				detected = "Docker"
			}
		} else if strings.Contains(content, "kubepods") || strings.Contains(content, "kubelet") {
			evidence = append(evidence, containerEvidence{"/proc/1/cgroup", "K8S", "kubepods found in cgroup"})
			detected = "Kubernetes"
		} else if strings.Contains(content, "lxc") {
			evidence = append(evidence, containerEvidence{"/proc/1/cgroup", "LXC", "lxc found in cgroup"})
			if detected == "none" {
				detected = "LXC"
			}
		} else if strings.Contains(content, "containerd") {
			evidence = append(evidence, containerEvidence{"/proc/1/cgroup", "CONTAINERD", "containerd found in cgroup"})
			if detected == "none" {
				detected = "containerd"
			}
		} else {
			evidence = append(evidence, containerEvidence{"/proc/1/cgroup", "clean", "no container indicators"})
		}
	}

	// Check /proc/1/environ for container_* vars
	if data, err := os.ReadFile("/proc/1/environ"); err == nil {
		content := string(data)
		structs.ZeroBytes(data) // opsec: environ may contain secrets/tokens
		if strings.Contains(content, "KUBERNETES_") {
			evidence = append(evidence, containerEvidence{"/proc/1/environ", "K8S", "KUBERNETES_* env vars present"})
			detected = "Kubernetes"
		}
		if strings.Contains(content, "container=") {
			evidence = append(evidence, containerEvidence{"/proc/1/environ", "CONTAINER", "container= env var found"})
		}
	}

	// Check for K8s service account
	if _, err := os.Stat("/var/run/secrets/kubernetes.io"); err == nil {
		evidence = append(evidence, containerEvidence{"K8s service account", "FOUND", "/var/run/secrets/kubernetes.io exists"})
		detected = "Kubernetes"
	} else {
		evidence = append(evidence, containerEvidence{"K8s service account", "absent", ""})
	}

	// Check for Docker socket mount (escape vector)
	for _, sock := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if info, err := os.Stat(sock); err == nil {
			evidence = append(evidence, containerEvidence{"Docker socket", "ESCAPE", fmt.Sprintf("%s accessible (mode: %s)", sock, info.Mode())})
		}
	}

	// Check /proc/1/sched for PID namespace
	if data, err := os.ReadFile("/proc/1/sched"); err == nil {
		lines := strings.SplitN(string(data), "\n", 2)
		structs.ZeroBytes(data) // opsec
		if len(lines) > 0 {
			// In containers, PID 1 is usually not systemd/init
			first := strings.TrimSpace(lines[0])
			if !strings.Contains(first, "systemd") && !strings.Contains(first, "init") {
				evidence = append(evidence, containerEvidence{"/proc/1/sched", "CONTAINER", fmt.Sprintf("PID 1 = %s", first)})
			} else {
				evidence = append(evidence, containerEvidence{"/proc/1/sched", "host", fmt.Sprintf("PID 1 = %s", first)})
			}
		}
	}

	// Check for WSL
	if data, err := os.ReadFile("/proc/version"); err == nil {
		content := strings.ToLower(string(data))
		structs.ZeroBytes(data) // opsec
		if strings.Contains(content, "microsoft") || strings.Contains(content, "wsl") {
			evidence = append(evidence, containerEvidence{"/proc/version", "WSL", "WSL kernel detected"})
			detected = "WSL"
		}
	}

	// Check capabilities (reduced caps = likely container)
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		content := string(data)
		structs.ZeroBytes(data) // opsec
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				cap := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
				if cap == "0000003fffffffff" || cap == "000001ffffffffff" {
					evidence = append(evidence, containerEvidence{"Capabilities (CapEff)", "full", cap})
				} else {
					evidence = append(evidence, containerEvidence{"Capabilities (CapEff)", "reduced", cap + " (may be containerized)"})
				}
				break
			}
		}

		// Identify dangerous capabilities for escape assessment
		dangerousCaps := identifyDangerousCaps(content)
		if len(dangerousCaps) > 0 {
			evidence = append(evidence, containerEvidence{"Dangerous Capabilities", "ESCAPE", strings.Join(dangerousCaps, ", ")})
		}

		// Check Seccomp status
		seccompStatus := parseSeccompStatus(content)
		if seccompStatus != "" {
			evidence = append(evidence, containerEvidence{"Seccomp", "info", seccompStatus})
		}
	}

	// Check for mounted host paths (escape vectors)
	if data, err := os.ReadFile("/proc/1/mounts"); err == nil {
		hostMounts := findHostMounts(string(data))
		structs.ZeroBytes(data) // opsec: mount info may reveal infrastructure
		for _, m := range hostMounts {
			evidence = append(evidence, containerEvidence{"Host Mount", "ESCAPE", fmt.Sprintf("%s at %s", m.Device, m.MountPoint)})
		}
	}

	// Check AppArmor profile
	if data, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		profile := strings.TrimSpace(string(data))
		structs.ZeroBytes(data) // opsec
		if profile == "unconfined" || profile == "" {
			evidence = append(evidence, containerEvidence{"AppArmor", "unconfined", "no AppArmor restrictions"})
		} else {
			evidence = append(evidence, containerEvidence{"AppArmor", "confined", profile})
		}
	}

	return evidence, detected
}

// dangerousCapBits maps bit positions to capability names that enable container escapes.
var dangerousCapBits = map[int]string{
	21: "CAP_SYS_ADMIN",
	16: "CAP_SYS_MODULE",
	19: "CAP_SYS_PTRACE",
	2:  "CAP_DAC_READ_SEARCH",
	12: "CAP_NET_ADMIN",
	25: "CAP_SYS_TIME",
}

// identifyDangerousCaps parses /proc/self/status content and returns escape-relevant capabilities.
func identifyDangerousCaps(statusContent string) []string {
	for _, line := range strings.Split(statusContent, "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			return parseDangerousCaps(hexStr)
		}
	}
	return nil
}

// parseDangerousCaps takes a hex capability bitmask and returns names of dangerous capabilities.
func parseDangerousCaps(hexStr string) []string {
	var val uint64
	for _, c := range hexStr {
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			val |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			val |= uint64(c - 'A' + 10)
		}
	}

	var found []string
	for bit, name := range dangerousCapBits {
		if val&(1<<uint(bit)) != 0 {
			found = append(found, name)
		}
	}
	return found
}

// parseSeccompStatus extracts Seccomp mode from /proc/self/status content.
func parseSeccompStatus(statusContent string) string {
	for _, line := range strings.Split(statusContent, "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
			switch val {
			case "0":
				return "disabled (no restrictions)"
			case "1":
				return "strict mode"
			case "2":
				return "filter mode (syscall filtering active)"
			default:
				return "mode " + val
			}
		}
	}
	return ""
}

func containerDetectDarwin() ([]containerEvidence, string) {
	var evidence []containerEvidence
	// macOS doesn't typically run in containers, but check for common patterns
	evidence = append(evidence, containerEvidence{"Platform", "macOS", "containers uncommon on macOS"})

	// Check for Docker Desktop or Orbstack
	if _, err := os.Stat("/Applications/Docker.app"); err == nil {
		evidence = append(evidence, containerEvidence{"Docker Desktop", "installed", "Docker Desktop found"})
	}
	if _, err := os.Stat("/Applications/OrbStack.app"); err == nil {
		evidence = append(evidence, containerEvidence{"OrbStack", "installed", "OrbStack found"})
	}

	return evidence, "none"
}

func containerDetectWindows() ([]containerEvidence, string) {
	var evidence []containerEvidence
	detected := "none"

	// Check for WSL from Windows side
	if _, err := os.Stat(`C:\Windows\System32\wsl.exe`); err == nil {
		evidence = append(evidence, containerEvidence{"WSL available", "yes", "wsl.exe found"})
	}

	// Check for Docker Desktop
	if _, err := os.Stat(`C:\Program Files\Docker\Docker\Docker Desktop.exe`); err == nil {
		evidence = append(evidence, containerEvidence{"Docker Desktop", "installed", "Docker Desktop found"})
	}

	// Check for Windows container indicators
	if _, err := os.Stat(`C:\ServiceProfiles`); err == nil {
		// Check if we're in a nano server / server core container
		if _, err := os.Stat(`C:\Windows\System32\ntoskrnl.exe`); os.IsNotExist(err) {
			evidence = append(evidence, containerEvidence{"Windows Container", "likely", "Nano Server/Server Core"})
			detected = "Windows Container"
		}
	}

	if len(evidence) == 0 {
		evidence = append(evidence, containerEvidence{"Platform", "Windows", "no container indicators found"})
	}

	return evidence, detected
}
