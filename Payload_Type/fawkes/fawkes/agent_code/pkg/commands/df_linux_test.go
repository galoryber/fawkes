//go:build linux

package commands

import (
	"testing"
)

func TestGetDiskFreeInfo_Live(t *testing.T) {
	entries, err := getDiskFreeInfo()
	if err != nil {
		t.Fatalf("getDiskFreeInfo failed: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("expected at least 1 filesystem entry")
	}

	// Root filesystem should always exist
	foundRoot := false
	for _, e := range entries {
		if e.mountpoint == "/" {
			foundRoot = true
			if e.total == 0 {
				t.Error("root filesystem total should be > 0")
			}
			if e.device == "" {
				t.Error("root filesystem device should not be empty")
			}
			if e.fstype == "" {
				t.Error("root filesystem type should not be empty")
			}
			break
		}
	}
	if !foundRoot {
		t.Error("expected root '/' filesystem in results")
	}
}

func TestGetDiskFreeInfo_UsedLessOrEqualTotal(t *testing.T) {
	entries, err := getDiskFreeInfo()
	if err != nil {
		t.Fatalf("getDiskFreeInfo failed: %v", err)
	}

	for _, e := range entries {
		if e.total > 0 && e.used > e.total {
			t.Errorf("filesystem %s: used (%d) > total (%d)", e.mountpoint, e.used, e.total)
		}
	}
}

func TestGetDiskFreeInfo_NoDuplicateMountpoints(t *testing.T) {
	entries, err := getDiskFreeInfo()
	if err != nil {
		t.Fatalf("getDiskFreeInfo failed: %v", err)
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		if seen[e.mountpoint] {
			t.Errorf("duplicate mountpoint: %s", e.mountpoint)
		}
		seen[e.mountpoint] = true
	}
}

func TestGetDiskFreeInfo_FiltersVirtualFS(t *testing.T) {
	entries, err := getDiskFreeInfo()
	if err != nil {
		t.Fatalf("getDiskFreeInfo failed: %v", err)
	}

	virtualTypes := map[string]bool{
		"sysfs": true, "proc": true, "devtmpfs": true, "devpts": true,
		"securityfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
		"debugfs": true, "tracefs": true, "hugetlbfs": true, "mqueue": true,
		"fusectl": true, "configfs": true, "binfmt_misc": true, "autofs": true,
		"efivarfs": true, "bpf": true, "nsfs": true,
	}

	for _, e := range entries {
		if virtualTypes[e.fstype] {
			t.Errorf("virtual filesystem %s (type %s) should be filtered out", e.mountpoint, e.fstype)
		}
	}
}

func TestGetDiskFreeInfo_MountpointsAbsolute(t *testing.T) {
	entries, err := getDiskFreeInfo()
	if err != nil {
		t.Fatalf("getDiskFreeInfo failed: %v", err)
	}

	for _, e := range entries {
		if len(e.mountpoint) == 0 || e.mountpoint[0] != '/' {
			t.Errorf("mountpoint should be absolute path, got %q", e.mountpoint)
		}
	}
}
