//go:build !windows

package commands

import (
	"fawkes/pkg/structs"
	"testing"
)

func TestDrivesUnixName(t *testing.T) {
	cmd := &DrivesUnixCommand{}
	if cmd.Name() != "drives" {
		t.Errorf("expected 'drives', got '%s'", cmd.Name())
	}
}

func TestDrivesUnixDescription(t *testing.T) {
	cmd := &DrivesUnixCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestShouldSkipFs(t *testing.T) {
	tests := []struct {
		fsType string
		device string
		skip   bool
	}{
		{"ext4", "/dev/sda1", false},
		{"xfs", "/dev/nvme0n1p1", false},
		{"apfs", "/dev/disk1s1", false},
		{"proc", "proc", true},
		{"sysfs", "sysfs", true},
		{"devpts", "devpts", true},
		{"cgroup2", "cgroup2", true},
		{"tmpfs", "none", true},     // device=none is skipped
		{"ext4", "systemd-1", true}, // systemd device is skipped
		{"tmpfs", "tmpfs", false},   // tmpfs with proper device is OK
		{"debugfs", "debugfs", true},
		{"bpf", "bpf", true},
		{"nfs", "server:/share", false}, // NFS mounts should not be skipped
		{"binfmt_misc", "binfmt_misc", true},
	}

	for _, tc := range tests {
		result := shouldSkipFs(tc.fsType, tc.device)
		if result != tc.skip {
			t.Errorf("shouldSkipFs(%q, %q) = %v, want %v", tc.fsType, tc.device, result, tc.skip)
		}
	}
}

func TestDrivesUnixExecute(t *testing.T) {
	cmd := &DrivesUnixCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("expected 'success', got '%s': %s", result.Status, result.Output)
	}
}

func TestGetMountPoints(t *testing.T) {
	mounts := getMountPoints()
	if len(mounts) == 0 {
		t.Skip("no mount points found")
	}
	// At least root should be present
	foundRoot := false
	for _, m := range mounts {
		if m.mountPoint == "/" {
			foundRoot = true
			break
		}
	}
	if !foundRoot {
		t.Error("expected root (/) mount point")
	}
}

func TestParseProcMountsData(t *testing.T) {
	lines := []string{
		"/dev/sda1 / ext4 rw,relatime 0 0",
		"/dev/sda2 /home xfs rw,relatime 0 0",
		"proc /proc proc rw,nosuid 0 0",
		"sysfs /sys sysfs rw,nosuid 0 0",
		"tmpfs /tmp tmpfs rw,nosuid 0 0",
		"none /run/user/1000 tmpfs rw 0 0",
		"server:/export /mnt/nfs nfs rw 0 0",
	}

	mounts := parseProcMountsData(lines)

	// Should include ext4, xfs, tmpfs (with real device), nfs
	// Should skip proc, sysfs, none (device)
	expected := map[string]string{
		"/":        "ext4",
		"/home":    "xfs",
		"/tmp":     "tmpfs",
		"/mnt/nfs": "nfs",
	}

	if len(mounts) != len(expected) {
		t.Fatalf("expected %d mounts, got %d: %+v", len(expected), len(mounts), mounts)
	}
	for _, m := range mounts {
		if want, ok := expected[m.mountPoint]; ok {
			if m.fsType != want {
				t.Errorf("mount %s: fsType=%q, want %q", m.mountPoint, m.fsType, want)
			}
		} else {
			t.Errorf("unexpected mount: %s (%s)", m.mountPoint, m.fsType)
		}
	}
}

func TestParseProcMountsData_Empty(t *testing.T) {
	mounts := parseProcMountsData(nil)
	if len(mounts) != 0 {
		t.Errorf("expected 0 mounts for nil input, got %d", len(mounts))
	}
}

func TestParseProcMountsData_ShortLines(t *testing.T) {
	lines := []string{"short", "two fields", ""}
	mounts := parseProcMountsData(lines)
	if len(mounts) != 0 {
		t.Errorf("expected 0 mounts for short lines, got %d", len(mounts))
	}
}

func TestParseMountOutput(t *testing.T) {
	// macOS-style mount output
	output := `/dev/disk1s1 on / (apfs, local, journaled)
/dev/disk1s2 on /System/Volumes/Data (apfs, local, journaled)
devfs on /dev (devfs, local, nobrowse)
/dev/disk2s1 on /Volumes/External (msdos, local, nodev, nosuid, noowners)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)
`

	mounts := parseMountOutput(output)

	// devfs → shouldSkipFs? No, "devfs" isn't in skipTypes. But device is "devfs" not "none"/"systemd-1"
	// autofs → yes, in skipTypes
	// So we should get: /, /System/Volumes/Data, /dev (devfs), /Volumes/External
	found := make(map[string]bool)
	for _, m := range mounts {
		found[m.mountPoint] = true
	}

	if !found["/"] {
		t.Error("expected / mount")
	}
	if !found["/System/Volumes/Data"] {
		t.Error("expected /System/Volumes/Data mount")
	}
	if !found["/Volumes/External"] {
		t.Error("expected /Volumes/External mount")
	}
	if found["/System/Volumes/Data/home"] {
		t.Error("autofs mount should be filtered out")
	}
}

func TestParseMountOutput_Empty(t *testing.T) {
	mounts := parseMountOutput("")
	if len(mounts) != 0 {
		t.Errorf("expected 0 mounts for empty output, got %d", len(mounts))
	}
}

func TestParseMountOutput_LinuxStyle(t *testing.T) {
	// Linux mount output uses the same format
	output := `/dev/sda1 on / (ext4, rw, relatime)
proc on /proc (proc, rw, nosuid)
sysfs on /sys (sysfs, rw, nosuid)
`
	mounts := parseMountOutput(output)
	if len(mounts) != 1 { // only ext4, proc and sysfs skipped
		t.Errorf("expected 1 mount, got %d: %+v", len(mounts), mounts)
	}
	if len(mounts) > 0 && mounts[0].mountPoint != "/" {
		t.Errorf("expected / mount, got %s", mounts[0].mountPoint)
	}
}

func TestParseMountOutput_MalformedLines(t *testing.T) {
	output := `no-on-keyword here
/dev/sda1 on / (ext4)
missing parens on /data
`
	mounts := parseMountOutput(output)
	if len(mounts) != 1 {
		t.Errorf("expected 1 valid mount, got %d: %+v", len(mounts), mounts)
	}
}
