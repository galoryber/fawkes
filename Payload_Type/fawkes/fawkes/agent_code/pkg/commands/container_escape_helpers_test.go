package commands

import (
	"strings"
	"testing"
)

// --- extractCgroupPath Tests ---

func TestExtractCgroupPath_Docker(t *testing.T) {
	content := `12:cpuset:/docker/abc123def456
11:devices:/docker/abc123def456
10:memory:/docker/abc123def456
9:blkio:/docker/abc123def456`
	got := extractCgroupPath(content)
	if got != "/docker/abc123def456" {
		t.Errorf("extractCgroupPath = %q, want %q", got, "/docker/abc123def456")
	}
}

func TestExtractCgroupPath_K8s(t *testing.T) {
	content := `12:cpuset:/kubepods/besteffort/pod-abc123/container-def456
11:devices:/kubepods/besteffort/pod-abc123/container-def456`
	got := extractCgroupPath(content)
	if !strings.HasPrefix(got, "/kubepods") {
		t.Errorf("extractCgroupPath = %q, want prefix /kubepods", got)
	}
}

func TestExtractCgroupPath_HostProcess(t *testing.T) {
	// On the host, all entries are "/"
	content := `12:cpuset:/
11:devices:/
10:memory:/`
	got := extractCgroupPath(content)
	if got != "" {
		t.Errorf("extractCgroupPath for host = %q, want empty", got)
	}
}

func TestExtractCgroupPath_Empty(t *testing.T) {
	got := extractCgroupPath("")
	if got != "" {
		t.Errorf("extractCgroupPath for empty = %q, want empty", got)
	}
}

func TestExtractCgroupPath_CgroupV2(t *testing.T) {
	// cgroup v2 uses a single hierarchy
	content := `0::/system.slice/docker-abc123.scope`
	got := extractCgroupPath(content)
	if got != "/system.slice/docker-abc123.scope" {
		t.Errorf("extractCgroupPath = %q, want %q", got, "/system.slice/docker-abc123.scope")
	}
}

func TestExtractCgroupPath_MixedRootAndContainer(t *testing.T) {
	// Some lines root, some container
	content := `12:cpuset:/
11:devices:/docker/abc123
10:memory:/`
	got := extractCgroupPath(content)
	if got != "/docker/abc123" {
		t.Errorf("extractCgroupPath = %q, want %q", got, "/docker/abc123")
	}
}

// --- cleanDockerLogs Tests ---

func TestCleanDockerLogs_Normal(t *testing.T) {
	// Docker log: 8-byte header + content
	raw := "\x01\x00\x00\x00\x00\x00\x00\x0dHello World\n\x01\x00\x00\x00\x00\x00\x00\x0dSecond Line"
	got := cleanDockerLogs(raw)
	if !strings.Contains(got, "Hello World") {
		t.Errorf("cleanDockerLogs should contain 'Hello World', got %q", got)
	}
	if !strings.Contains(got, "Second Line") {
		t.Errorf("cleanDockerLogs should contain 'Second Line', got %q", got)
	}
}

func TestCleanDockerLogs_Empty(t *testing.T) {
	got := cleanDockerLogs("")
	if got != "" {
		t.Errorf("cleanDockerLogs for empty = %q, want empty", got)
	}
}

func TestCleanDockerLogs_ShortLines(t *testing.T) {
	// Lines shorter than 8 chars pass through
	got := cleanDockerLogs("short")
	if !strings.Contains(got, "short") {
		t.Errorf("cleanDockerLogs should pass through short lines, got %q", got)
	}
}

func TestCleanDockerLogs_StdoutAndStderr(t *testing.T) {
	// \x01 = stdout, \x02 = stderr
	raw := "\x01\x00\x00\x00\x00\x00\x00\x05stdout line\n\x02\x00\x00\x00\x00\x00\x00\x05stderr line"
	got := cleanDockerLogs(raw)
	if !strings.Contains(got, "stdout line") {
		t.Errorf("cleanDockerLogs should contain stdout, got %q", got)
	}
	if !strings.Contains(got, "stderr line") {
		t.Errorf("cleanDockerLogs should contain stderr, got %q", got)
	}
}

// --- parseCapEff Tests ---

func TestParseCapEff_Normal(t *testing.T) {
	status := `Name:	bash
Umask:	0022
State:	S (sleeping)
CapInh:	0000000000000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000`
	got := parseCapEff(status)
	if got != "000001ffffffffff" {
		t.Errorf("parseCapEff = %q, want %q", got, "000001ffffffffff")
	}
}

func TestParseCapEff_Unprivileged(t *testing.T) {
	status := `Name:	sh
CapEff:	00000000a80425fb`
	got := parseCapEff(status)
	if got != "00000000a80425fb" {
		t.Errorf("parseCapEff = %q, want %q", got, "00000000a80425fb")
	}
}

func TestParseCapEff_NoCapEff(t *testing.T) {
	status := `Name:	bash
State:	S`
	got := parseCapEff(status)
	if got != "" {
		t.Errorf("parseCapEff with no CapEff = %q, want empty", got)
	}
}

func TestParseCapEff_Empty(t *testing.T) {
	got := parseCapEff("")
	if got != "" {
		t.Errorf("parseCapEff for empty = %q, want empty", got)
	}
}

// --- isFullCaps Tests ---

func TestIsFullCaps_Privileged(t *testing.T) {
	privilegedCaps := []string{
		"0000003fffffffff", // kernel <5.8
		"000001ffffffffff", // kernel 5.8-5.16
		"000003ffffffffff", // kernel 5.17+
	}
	for _, cap := range privilegedCaps {
		if !isFullCaps(cap) {
			t.Errorf("isFullCaps(%q) = false, want true", cap)
		}
	}
}

func TestIsFullCaps_Unprivileged(t *testing.T) {
	unprivilegedCaps := []string{
		"00000000a80425fb",
		"0000000000000000",
		"",
		"00000020000425fb",
	}
	for _, cap := range unprivilegedCaps {
		if isFullCaps(cap) {
			t.Errorf("isFullCaps(%q) = true, want false", cap)
		}
	}
}

// --- findHostMounts Tests ---

func TestFindHostMounts_WithHostMount(t *testing.T) {
	procMounts := `/dev/sda1 /host ext4 rw,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0`
	mounts := findHostMounts(procMounts)
	if len(mounts) != 1 {
		t.Fatalf("findHostMounts returned %d mounts, want 1", len(mounts))
	}
	if mounts[0].MountPoint != "/host" {
		t.Errorf("mount point = %q, want %q", mounts[0].MountPoint, "/host")
	}
}

func TestFindHostMounts_NoHostMount(t *testing.T) {
	procMounts := `overlay / overlay rw 0 0
proc /proc proc rw 0 0
tmpfs /dev/shm tmpfs rw 0 0`
	mounts := findHostMounts(procMounts)
	if len(mounts) != 0 {
		t.Errorf("findHostMounts returned %d mounts, want 0", len(mounts))
	}
}

func TestFindHostMounts_MultipleHostMounts(t *testing.T) {
	procMounts := `/dev/sda1 /host/root ext4 rw 0 0
/dev/sda1 /hostfs ext4 rw 0 0
proc /proc proc rw 0 0`
	mounts := findHostMounts(procMounts)
	if len(mounts) != 2 {
		t.Errorf("findHostMounts returned %d mounts, want 2", len(mounts))
	}
}

func TestFindHostMounts_Empty(t *testing.T) {
	mounts := findHostMounts("")
	if len(mounts) != 0 {
		t.Errorf("findHostMounts for empty = %d mounts, want 0", len(mounts))
	}
}

func TestFindHostMounts_SdaMountAtSlash(t *testing.T) {
	// /dev/sda1 mounted at / (root of container — normal, NOT host mount)
	procMounts := `/dev/sda1 / ext4 rw 0 0
proc /proc proc rw 0 0`
	mounts := findHostMounts(procMounts)
	if len(mounts) != 1 {
		t.Errorf("findHostMounts with /dev/sda1 at / returned %d mounts, want 1", len(mounts))
	}
}

// --- Constants Tests ---

func TestDockerSocketPaths(t *testing.T) {
	if len(dockerSocketPaths) < 2 {
		t.Error("dockerSocketPaths should have at least 2 entries")
	}
	for _, p := range dockerSocketPaths {
		if !strings.HasSuffix(p, "docker.sock") {
			t.Errorf("unexpected docker socket path: %q", p)
		}
	}
}

func TestHostBlockDevices(t *testing.T) {
	if len(hostBlockDevices) < 3 {
		t.Error("hostBlockDevices should have at least 3 entries")
	}
	for _, d := range hostBlockDevices {
		if !strings.HasPrefix(d, "/dev/") {
			t.Errorf("block device should start with /dev/: %q", d)
		}
	}
}

func TestK8sTokenPath(t *testing.T) {
	if !strings.Contains(k8sTokenPath, "kubernetes.io") {
		t.Errorf("k8sTokenPath should contain kubernetes.io: %q", k8sTokenPath)
	}
}
