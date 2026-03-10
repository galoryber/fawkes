//go:build linux

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestGetMountInfoLive(t *testing.T) {
	entries, err := getMountInfo()
	if err != nil {
		t.Fatalf("getMountInfo() error: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("expected at least one mount entry on Linux")
	}

	// Every entry should have non-empty fields
	for i, e := range entries {
		if e.device == "" {
			t.Errorf("entry[%d]: empty device", i)
		}
		if e.mntPoint == "" {
			t.Errorf("entry[%d]: empty mount point", i)
		}
		if e.mntType == "" {
			t.Errorf("entry[%d]: empty mount type", i)
		}
		if e.mntOpts == "" {
			t.Errorf("entry[%d]: empty mount options", i)
		}
	}
}

func TestGetMountInfoContainsRoot(t *testing.T) {
	entries, err := getMountInfo()
	if err != nil {
		t.Fatalf("getMountInfo() error: %v", err)
	}

	found := false
	for _, e := range entries {
		if e.mntPoint == "/" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find root (/) mount point")
	}
}

func TestGetMountInfoContainsProc(t *testing.T) {
	entries, err := getMountInfo()
	if err != nil {
		t.Fatalf("getMountInfo() error: %v", err)
	}

	found := false
	for _, e := range entries {
		if e.mntPoint == "/proc" && e.mntType == "proc" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find /proc mount point with type proc")
	}
}

func TestMountCommandExecuteLive(t *testing.T) {
	cmd := &MountCommand{}
	result := cmd.Execute(structs.Task{})

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	if result.Output == "" {
		t.Error("expected non-empty output")
	}

	// Output should have table header
	if !strings.Contains(result.Output, "Device") || !strings.Contains(result.Output, "Mount Point") {
		t.Error("expected table headers in output")
	}

	// Output should contain mount point count
	if !strings.Contains(result.Output, "mount points") {
		t.Error("expected mount point count in output")
	}
}

func TestMountCommandName(t *testing.T) {
	cmd := &MountCommand{}
	if cmd.Name() != "mount" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "mount")
	}
}

func TestMountCommandDescription(t *testing.T) {
	cmd := &MountCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "mount") {
		t.Error("description should mention mount")
	}
}
