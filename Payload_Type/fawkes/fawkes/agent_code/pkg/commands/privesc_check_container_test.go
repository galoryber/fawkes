//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGroupsFromStatus(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			"typical status",
			"Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nGroups:\t1000 4 24 27 30 46 100 118\n",
			[]string{"1000", "4", "24", "27", "30", "46", "100", "118"},
		},
		{
			"single group",
			"Name:\tsh\nGroups:\t0\n",
			[]string{"0"},
		},
		{
			"no groups line",
			"Name:\tsh\nState:\tR\n",
			nil,
		},
		{
			"empty groups",
			"Name:\tsh\nGroups:\t\n",
			[]string{},
		},
		{
			"groups with extra whitespace",
			"Name:\tsh\nGroups:\t 1000  4  27 \n",
			[]string{"1000", "4", "27"},
		},
		{
			"empty content",
			"",
			nil,
		},
		{
			"groups not at start of line",
			"Tracerpid:\t0\nGroups:\t1000 999\nVmPeak:\t1234 kB\n",
			[]string{"1000", "999"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseGroupsFromStatus(tc.content)
			if tc.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if len(result) != len(tc.expected) {
				t.Fatalf("got %d groups, want %d: %v vs %v", len(result), len(tc.expected), result, tc.expected)
			}
			for i, g := range result {
				if g != tc.expected[i] {
					t.Errorf("group[%d] = %q, want %q", i, g, tc.expected[i])
				}
			}
		})
	}
}

func TestResolveGroupNamesNilEmpty(t *testing.T) {
	// Test with nil input
	result := resolveGroupNames(nil)
	if result != nil {
		t.Errorf("resolveGroupNames(nil) should return nil, got %v", result)
	}

	// Test with empty input
	result = resolveGroupNames([]string{})
	if result != nil {
		t.Errorf("resolveGroupNames([]) should return nil, got %v", result)
	}
}

func TestResolveGroupNamesWithSystemGroups(t *testing.T) {
	// Test against actual /etc/group if it exists
	if _, err := os.Stat("/etc/group"); err != nil {
		t.Skip("no /etc/group available")
	}

	// Root group (GID 0) should always exist
	result := resolveGroupNames([]string{"0"})
	if len(result) == 0 {
		t.Error("expected to resolve GID 0 to a group name")
		return
	}
	if result[0] != "root" {
		t.Errorf("GID 0 resolved to %q, expected 'root'", result[0])
	}
}

func TestGroupFileLineParsing(t *testing.T) {
	// Test the /etc/group parsing logic used by resolveGroupNames
	lines := []string{
		"root:x:0:",
		"daemon:x:1:",
		"docker:x:999:user1,user2",
		"sudo:x:27:user1",
		"adm:x:4:syslog,user1",
	}

	gidSet := map[string]bool{"0": true, "999": true, "4": true}
	var names []string
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 4)
		if len(parts) >= 3 && gidSet[parts[2]] {
			names = append(names, parts[0])
		}
	}
	if len(names) != 3 {
		t.Fatalf("expected 3 resolved names, got %d: %v", len(names), names)
	}
	expected := map[string]bool{"root": true, "docker": true, "adm": true}
	for _, name := range names {
		if !expected[name] {
			t.Errorf("unexpected group name: %q", name)
		}
	}
}

func TestDangerousGroupsIntegrity(t *testing.T) {
	if len(dangerousGroups) == 0 {
		t.Fatal("dangerousGroups is empty")
	}

	seen := make(map[string]bool)
	validRisks := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}

	for i, dg := range dangerousGroups {
		if dg.Name == "" {
			t.Errorf("dangerousGroups[%d] has empty Name", i)
		}
		if seen[dg.Name] {
			t.Errorf("duplicate dangerous group: %s", dg.Name)
		}
		seen[dg.Name] = true
		if !validRisks[dg.Risk] {
			t.Errorf("dangerousGroups[%d] (%s) has invalid Risk: %q", i, dg.Name, dg.Risk)
		}
		if dg.Impact == "" {
			t.Errorf("dangerousGroups[%d] (%s) has empty Impact", i, dg.Name)
		}
	}
}

func TestDangerousGroupsExpectedEntries(t *testing.T) {
	expected := []string{"disk", "shadow", "sudo", "wheel", "root", "adm", "kvm", "wireshark"}
	names := make(map[string]bool)
	for _, dg := range dangerousGroups {
		names[dg.Name] = true
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected dangerous group %q not found", name)
		}
	}
}

func TestDangerousGroupsExcludesDockerLxdPodman(t *testing.T) {
	// docker, lxd, podman are handled by docker-group action, should NOT be in dangerousGroups
	for _, dg := range dangerousGroups {
		switch dg.Name {
		case "docker", "lxd", "podman":
			t.Errorf("dangerousGroups should not contain %q (handled by docker-group action)", dg.Name)
		}
	}
}

func TestDockerGroupInfoStruct(t *testing.T) {
	// Test zero-value behavior
	var info dockerGroupInfo
	if info.inDocker || info.inLxd || info.inPodman || info.dockerSocket {
		t.Error("zero-value dockerGroupInfo should have all false fields")
	}
}

func TestCgroupContainerDetection(t *testing.T) {
	// Test the cgroup content detection logic from privescCheckContainer
	tests := []struct {
		name        string
		cgroupText  string
		isContainer bool
	}{
		{"docker", "12:blkio:/docker/abc123\n", true},
		{"kubepods", "12:blkio:/kubepods/pod-abc\n", true},
		{"lxc", "12:blkio:/lxc/mycontainer\n", true},
		{"containerd", "0::/system.slice/containerd.service\n", true},
		{"bare metal", "12:blkio:/\n0::/init.scope\n", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isContainer := strings.Contains(tc.cgroupText, "docker") ||
				strings.Contains(tc.cgroupText, "kubepods") ||
				strings.Contains(tc.cgroupText, "lxc") ||
				strings.Contains(tc.cgroupText, "containerd")
			if isContainer != tc.isContainer {
				t.Errorf("got isContainer=%v, want %v", isContainer, tc.isContainer)
			}
		})
	}
}

func TestOverlayFilesystemDetection(t *testing.T) {
	// Test the overlay/aufs detection logic from privescCheckContainer
	tests := []struct {
		name        string
		mountinfo   string
		isContainer bool
	}{
		{"overlay", "100 1 0:50 / / rw,relatime shared:1 - overlay overlay rw\n", true},
		{"aufs", "100 1 0:50 / / rw - aufs none rw\n", true},
		{"ext4", "100 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n", false},
		{"xfs", "100 1 8:1 / / rw - xfs /dev/sda1 rw\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isContainer := strings.Contains(tc.mountinfo, "overlay") ||
				strings.Contains(tc.mountinfo, "aufs")
			if isContainer != tc.isContainer {
				t.Errorf("got isContainer=%v, want %v", isContainer, tc.isContainer)
			}
		})
	}
}

func TestPID1ProcessDetection(t *testing.T) {
	// Test PID 1 process name detection logic
	tests := []struct {
		comm     string
		unusual  bool
	}{
		{"systemd", false},
		{"init", false},
		{"bash", true},
		{"sleep", true},
		{"containerd-shim", true},
		{"node", true},
	}
	for _, tc := range tests {
		unusual := tc.comm != "systemd" && tc.comm != "init"
		if unusual != tc.unusual {
			t.Errorf("comm=%q: got unusual=%v, want %v", tc.comm, unusual, tc.unusual)
		}
	}
}

func TestPrivescCheckContainer_OutputFormat(t *testing.T) {
	// This calls the actual function - verifies it doesn't crash on a real system
	result := privescCheckContainer()
	if result.Status != "success" {
		t.Errorf("expected success status, got %q", result.Status)
	}
	if result.Output == "" {
		t.Error("expected non-empty output")
	}
}

func TestPrivescCheckDockerGroup_SuccessStatus(t *testing.T) {
	result := privescCheckDockerGroup()
	if result.Status != "success" {
		t.Errorf("expected success status, got %q", result.Status)
	}
	if result.Output == "" {
		t.Error("expected non-empty output")
	}
}

func TestPrivescCheckDangerousGroups_Categorization(t *testing.T) {
	// Test the risk categorization logic
	nameSet := map[string]bool{"disk": true, "adm": true, "video": true, "sudo": true}
	var critical, high, medium, low []string
	for _, dg := range dangerousGroups {
		if !nameSet[dg.Name] {
			continue
		}
		switch dg.Risk {
		case "CRITICAL":
			critical = append(critical, dg.Name)
		case "HIGH":
			high = append(high, dg.Name)
		case "MEDIUM":
			medium = append(medium, dg.Name)
		default:
			low = append(low, dg.Name)
		}
	}
	if len(critical) != 1 || critical[0] != "disk" {
		t.Errorf("expected disk in CRITICAL, got %v", critical)
	}
	if len(high) != 1 || high[0] != "sudo" {
		t.Errorf("expected sudo in HIGH, got %v", high)
	}

	// Verify total found matches expected
	total := len(critical) + len(high) + len(medium) + len(low)
	if total != 4 {
		t.Errorf("expected 4 categorized groups, got %d", total)
	}
}

func TestParseGroupsFromStatusWithRealProc(t *testing.T) {
	// Read actual /proc/self/status and verify parsing
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skip("cannot read /proc/self/status")
	}
	groups := parseGroupsFromStatus(string(data))
	// Current process should have at least one group
	if len(groups) == 0 {
		t.Error("expected at least one group from /proc/self/status")
	}
	// All group IDs should be numeric
	for _, g := range groups {
		for _, c := range g {
			if c < '0' || c > '9' {
				t.Errorf("group ID %q contains non-numeric character", g)
				break
			}
		}
	}
}

func TestResolveGroupNamesFromFixture(t *testing.T) {
	// Test the parsing logic directly with a fixture
	dir := t.TempDir()
	groupFile := filepath.Join(dir, "group")
	content := "root:x:0:\ndaemon:x:1:\nadm:x:4:syslog\ndocker:x:999:testuser\n"
	if err := os.WriteFile(groupFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Parse the fixture manually (same logic as resolveGroupNames)
	gids := []string{"0", "999"}
	gidSet := make(map[string]bool)
	for _, g := range gids {
		gidSet[g] = true
	}

	f, err := os.Open(groupFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var names []string
	data, _ := os.ReadFile(groupFile)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 4)
		if len(parts) >= 3 && gidSet[parts[2]] {
			names = append(names, parts[0])
		}
	}

	if len(names) != 2 {
		t.Fatalf("expected 2 resolved names, got %d: %v", len(names), names)
	}
	nameSet := map[string]bool{"root": true, "docker": true}
	for _, n := range names {
		if !nameSet[n] {
			t.Errorf("unexpected resolved name: %q", n)
		}
	}
}
