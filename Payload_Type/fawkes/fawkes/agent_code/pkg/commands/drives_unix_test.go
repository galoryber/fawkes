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
		{"tmpfs", "none", true},          // device=none is skipped
		{"ext4", "systemd-1", true},       // systemd device is skipped
		{"tmpfs", "tmpfs", false},         // tmpfs with proper device is OK
		{"debugfs", "debugfs", true},
		{"bpf", "bpf", true},
		{"nfs", "server:/share", false},   // NFS mounts should not be skipped
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
