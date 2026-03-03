package commands

// container_escape_helpers.go contains pure helper functions extracted from
// container_escape.go for cross-platform testing without container access.
// No build tags — these are testable on any platform.

import "strings"

// extractCgroupPath gets the container's cgroup path from /proc/1/cgroup content.
// Returns the first non-root cgroup path found, or empty string.
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
// Docker's multiplexed attach protocol prepends an 8-byte header to every line:
// [stream_type(1)][padding(3)][size(4)]. This strips that prefix.
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

// parseCapEff extracts the CapEff value from /proc/self/status content.
// Returns the hex capability string or empty if not found.
func parseCapEff(statusContent string) string {
	for _, line := range strings.Split(statusContent, "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	return ""
}

// isFullCaps returns true if the effective capability hex value indicates
// a privileged container (all capabilities granted).
func isFullCaps(capEff string) bool {
	// Known full-capability values across kernel versions
	switch capEff {
	case "0000003fffffffff", // kernel <5.8
		"000001ffffffffff", // kernel 5.8-5.16
		"000003ffffffffff": // kernel 5.17+
		return true
	}
	return false
}

// findHostMounts extracts potential host filesystem mount points from /proc/mounts content.
// Returns mount points that indicate host filesystem access (e.g., /host* or root device mounts).
func findHostMounts(procMounts string) []hostMount {
	var mounts []hostMount
	for _, line := range strings.Split(procMounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		device := fields[0]
		mountpoint := fields[1]
		if strings.HasPrefix(mountpoint, "/host") ||
			(strings.HasPrefix(mountpoint, "/") && device == "/dev/sda1") {
			mounts = append(mounts, hostMount{Device: device, MountPoint: mountpoint})
		}
	}
	return mounts
}

// hostMount represents a detected host filesystem mount inside a container.
type hostMount struct {
	Device     string
	MountPoint string
}

// dockerSocketPaths lists known Docker socket locations to check.
var dockerSocketPaths = []string{"/var/run/docker.sock", "/run/docker.sock"}

// hostBlockDevices lists common host block device paths.
var hostBlockDevices = []string{"/dev/sda", "/dev/vda", "/dev/xvda", "/dev/nvme0n1"}

// k8sTokenPath is the standard Kubernetes service account token location.
const k8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
