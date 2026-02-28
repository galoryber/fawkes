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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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
		if strings.Contains(content, "microsoft") || strings.Contains(content, "wsl") {
			evidence = append(evidence, containerEvidence{"/proc/version", "WSL", "WSL kernel detected"})
			detected = "WSL"
		}
	}

	// Check capabilities (reduced caps = likely container)
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
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
	}

	return evidence, detected
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
