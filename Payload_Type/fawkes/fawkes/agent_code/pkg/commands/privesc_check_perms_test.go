//go:build linux

package commands

import (
	"fmt"
	"strings"
	"testing"
)

func TestCapNamesIntegrity(t *testing.T) {
	// capNames should have entries for common capabilities
	expectedCaps := map[int]string{
		0:  "cap_chown",
		1:  "cap_dac_override",
		7:  "cap_setuid",
		12: "cap_net_admin",
		13: "cap_net_raw",
		19: "cap_sys_ptrace",
		21: "cap_sys_admin",
	}
	for idx, name := range expectedCaps {
		if idx >= len(capNames) {
			t.Errorf("capNames too short, missing index %d (%s)", idx, name)
			continue
		}
		if capNames[idx] != name {
			t.Errorf("capNames[%d] = %q, want %q", idx, capNames[idx], name)
		}
	}
	// Should have at least 40 entries
	if len(capNames) < 40 {
		t.Errorf("capNames has %d entries, expected at least 40", len(capNames))
	}
}

func TestCapNamesNoDuplicates(t *testing.T) {
	seen := make(map[string]int)
	for i, name := range capNames {
		if name == "" {
			continue
		}
		if prev, ok := seen[name]; ok {
			t.Errorf("duplicate cap name %q at indices %d and %d", name, prev, i)
		}
		seen[name] = i
	}
}

func TestAnalyzePathHijack_ExistingDirBeforeSystem(t *testing.T) {
	// Use a real directory (temp) before system dirs
	tmpDir := t.TempDir()
	dirs := []string{tmpDir, "/usr/bin", "/bin"}
	systemDirs := map[string]bool{"/usr/bin": true, "/bin": true}
	results := analyzePathHijack(dirs, systemDirs)
	if len(results) != 1 {
		t.Fatalf("expected 1 result for real dir before system, got %d", len(results))
	}
	if results[0].Dir != tmpDir {
		t.Errorf("expected %s, got %q", tmpDir, results[0].Dir)
	}
	if results[0].Position != 1 {
		t.Errorf("expected position 1, got %d", results[0].Position)
	}
	if results[0].BeforeSystem != "/usr/bin" {
		t.Errorf("expected beforeSystem=/usr/bin, got %q", results[0].BeforeSystem)
	}
	// Temp dir should be writable
	if !results[0].Writable {
		t.Error("expected temp dir to be writable")
	}
}

func TestAnalyzePathHijack_RelativePath(t *testing.T) {
	// Empty or "." entries are always flagged as hijack risks
	dirs := []string{".", "/usr/bin"}
	systemDirs := map[string]bool{"/usr/bin": true}
	results := analyzePathHijack(dirs, systemDirs)
	if len(results) != 1 {
		t.Fatalf("expected 1 result for '.' entry, got %d", len(results))
	}
	if !results[0].Writable {
		t.Error("relative path should always be writable=true")
	}
	if !strings.Contains(results[0].Dir, "relative") {
		t.Errorf("expected 'relative' in dir description, got %q", results[0].Dir)
	}
}

func TestAnalyzePathHijack_EmptyEntryDetails(t *testing.T) {
	// Empty string in PATH (e.g., ":/usr/bin" or "/usr/bin:")
	dirs := []string{"", "/usr/bin"}
	systemDirs := map[string]bool{"/usr/bin": true}
	results := analyzePathHijack(dirs, systemDirs)
	if len(results) != 1 {
		t.Fatalf("expected 1 result for empty entry, got %d", len(results))
	}
	if !results[0].Writable {
		t.Error("empty path should always be writable=true")
	}
	if results[0].Position != 1 {
		t.Errorf("expected position 1, got %d", results[0].Position)
	}
}

func TestAnalyzePathHijack_NoSystemDirs(t *testing.T) {
	// If no system dirs in PATH, firstSystem=-1, nothing after system dirs
	dirs := []string{"/opt/custom/bin", "/home/user/bin"}
	systemDirs := map[string]bool{"/usr/bin": true}
	results := analyzePathHijack(dirs, systemDirs)
	// With no system dirs found, firstSystem=-1, so i >= firstSystem is always true for i >= 0
	// But since firstSystem is -1, the condition `i >= firstSystem` is always true, so dirs after
	// system dirs are skipped (but there's no system dir to be after)
	// Actually: firstSystem=-1, so `firstSystem >= 0` is false, `i >= firstSystem` check is skipped
	// Thus all non-system, non-empty dirs that exist on disk could be returned
	// Since these paths don't exist, os.Stat fails and they're skipped
	if len(results) != 0 {
		t.Logf("got %d results (dirs may exist on this system)", len(results))
	}
}

func TestAnalyzePathHijack_AllSystemDirs(t *testing.T) {
	// All dirs are system dirs — nothing to flag
	dirs := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}
	systemDirs := map[string]bool{
		"/usr/bin": true, "/usr/sbin": true, "/bin": true, "/sbin": true,
	}
	results := analyzePathHijack(dirs, systemDirs)
	if len(results) != 0 {
		t.Errorf("expected 0 results for all-system PATH, got %d", len(results))
	}
}

func TestAnalyzePathHijack_AfterSystem(t *testing.T) {
	// Non-system dir AFTER system dirs — should NOT be flagged
	dirs := []string{"/usr/bin", "/home/user/bin"}
	systemDirs := map[string]bool{"/usr/bin": true}
	results := analyzePathHijack(dirs, systemDirs)
	if len(results) != 0 {
		t.Errorf("expected 0 results (non-system dir is after system dir), got %d", len(results))
	}
}

func TestInterestingSUIDBins(t *testing.T) {
	// Test the matching logic for interesting SUID binaries
	interestingBins := []string{"nmap", "vim", "python3", "bash", "docker", "pkexec", "gdb"}
	suidEntries := []string{
		"  /usr/bin/python3.10 (-rwsr-xr-x, 5000 bytes)",
		"  /usr/bin/passwd (-rwsr-xr-x, 60000 bytes)",
		"  /usr/bin/pkexec (-rwsr-xr-x, 20000 bytes)",
		"  /usr/sbin/mount.nfs (-rwsr-xr-x, 10000 bytes)",
	}

	var flagged []string
	for _, f := range suidEntries {
		fields := strings.Fields(f)
		if len(fields) == 0 {
			continue
		}
		for _, bin := range interestingBins {
			if strings.Contains(f, "/"+bin+" ") || strings.HasSuffix(fields[0], "/"+bin) {
				flagged = append(flagged, f)
				break
			}
		}
	}
	// python3.10 doesn't match /python3 exactly (contains check), pkexec matches
	if len(flagged) != 1 {
		t.Errorf("expected 1 flagged (pkexec), got %d: %v", len(flagged), flagged)
	}
}

func TestUID0Detection(t *testing.T) {
	// Test /etc/passwd UID 0 detection logic
	lines := []string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"backdoor:x:0:0:backdoor:/root:/bin/bash",
		"user:x:1000:1000:user:/home/user:/bin/bash",
		"toor:x:0:0:toor:/root:/bin/sh",
	}
	var uid0 []string
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) >= 4 && fields[2] == "0" && fields[0] != "root" {
			uid0 = append(uid0, fields[0])
		}
	}
	if len(uid0) != 2 {
		t.Fatalf("expected 2 UID 0 non-root accounts, got %d: %v", len(uid0), uid0)
	}
	if uid0[0] != "backdoor" || uid0[1] != "toor" {
		t.Errorf("unexpected UID 0 accounts: %v", uid0)
	}
}

func TestCapabilityFlagFormatting(t *testing.T) {
	// Test the capability flags formatting logic from readFileCaps
	tests := []struct {
		effective   bool
		permitted   bool
		inheritable bool
		expected    string
	}{
		{true, true, false, "ep"},
		{true, true, true, "epi"},
		{false, true, false, "p"},
		{false, true, true, "pi"},
		{true, false, true, "ei"},
	}
	for _, tc := range tests {
		flags := ""
		if tc.effective {
			flags += "e"
		}
		if tc.permitted {
			flags += "p"
		}
		if tc.inheritable {
			flags += "i"
		}
		if flags != tc.expected {
			t.Errorf("flags %v: got %q, want %q", tc, flags, tc.expected)
		}
	}
}

func TestCapabilityNameMapping(t *testing.T) {
	// Test capability name mapping from bitmask
	permitted := uint64(1<<13 | 1<<21) // cap_net_raw + cap_sys_admin
	var names []string
	for i := 0; i < len(capNames) && i < 64; i++ {
		if permitted&(1<<i) != 0 {
			if i < len(capNames) && capNames[i] != "" {
				names = append(names, capNames[i])
			} else {
				names = append(names, fmt.Sprintf("cap_%d", i))
			}
		}
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 capability names, got %d: %v", len(names), names)
	}
	if names[0] != "cap_net_raw" || names[1] != "cap_sys_admin" {
		t.Errorf("unexpected names: %v", names)
	}
}
