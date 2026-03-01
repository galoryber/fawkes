//go:build linux

package commands

import (
	"os"
	"testing"
)

func TestParseMemoryMaps_Self(t *testing.T) {
	// Parse the current process's memory maps
	regions, err := parseMemoryMaps(os.Getpid())
	if err != nil {
		t.Fatalf("parseMemoryMaps(self) failed: %v", err)
	}

	if len(regions) == 0 {
		t.Fatal("expected at least one memory region for current process")
	}

	// Verify basic structure of regions
	for i, r := range regions {
		if r.End <= r.Start {
			t.Errorf("region %d: end (0x%X) <= start (0x%X)", i, r.End, r.Start)
		}
		if r.Perms == "" {
			t.Errorf("region %d: empty permissions", i)
		}
		if len(r.Perms) < 4 {
			t.Errorf("region %d: permissions too short: %q", i, r.Perms)
		}
	}
}

func TestParseMemoryMaps_HasReadableRegions(t *testing.T) {
	regions, err := parseMemoryMaps(os.Getpid())
	if err != nil {
		t.Fatalf("parseMemoryMaps failed: %v", err)
	}

	readableCount := 0
	for _, r := range regions {
		if len(r.Perms) > 0 && r.Perms[0] == 'r' {
			readableCount++
		}
	}

	if readableCount == 0 {
		t.Error("expected at least one readable memory region")
	}
}

func TestParseMemoryMaps_HasExecutableRegion(t *testing.T) {
	regions, err := parseMemoryMaps(os.Getpid())
	if err != nil {
		t.Fatalf("parseMemoryMaps failed: %v", err)
	}

	hasExec := false
	for _, r := range regions {
		if len(r.Perms) >= 3 && r.Perms[2] == 'x' {
			hasExec = true
			break
		}
	}

	if !hasExec {
		t.Error("expected at least one executable memory region (code segment)")
	}
}

func TestParseMemoryMaps_PathsPresent(t *testing.T) {
	regions, err := parseMemoryMaps(os.Getpid())
	if err != nil {
		t.Fatalf("parseMemoryMaps failed: %v", err)
	}

	pathCount := 0
	for _, r := range regions {
		if r.Path != "" {
			pathCount++
		}
	}

	if pathCount == 0 {
		t.Error("expected at least some regions with paths (shared libraries, executable)")
	}
}

func TestParseMemoryMaps_InvalidPID(t *testing.T) {
	_, err := parseMemoryMaps(999999999)
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}

func TestParseMemoryMaps_PID1(t *testing.T) {
	// PID 1 may or may not be readable depending on permissions
	regions, err := parseMemoryMaps(1)
	if err != nil {
		// Expected on systems where we can't read PID 1's maps
		t.Logf("PID 1 maps not readable (expected): %v", err)
		return
	}
	if len(regions) == 0 {
		t.Error("PID 1 maps readable but empty")
	}
}

func TestScanProcessMemory_SelfSearch(t *testing.T) {
	// Search for a known string in our own process memory
	// This string should exist in the binary
	needle := "TestScanProcessMemory_SelfSearch"
	matches, regionsScanned, bytesScanned, err := scanProcessMemory(os.Getpid(), []byte(needle), 5, 16)
	if err != nil {
		t.Fatalf("scanProcessMemory failed: %v", err)
	}

	if regionsScanned == 0 {
		t.Error("no regions were scanned")
	}
	if bytesScanned == 0 {
		t.Error("zero bytes scanned")
	}

	// The needle should be found at least once (in our own binary)
	if len(matches) == 0 {
		t.Error("expected to find the test function name in own process memory")
	}

	// Verify match structure
	for i, m := range matches {
		if m.MatchLen != len(needle) {
			t.Errorf("match %d: expected matchLen %d, got %d", i, len(needle), m.MatchLen)
		}
		if m.Address == 0 {
			t.Errorf("match %d: address should not be 0", i)
		}
	}
}


func TestScanProcessMemory_InvalidPID(t *testing.T) {
	_, _, _, err := scanProcessMemory(999999999, []byte("test"), 10, 16)
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}
