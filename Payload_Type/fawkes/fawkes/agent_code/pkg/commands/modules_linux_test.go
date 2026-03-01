//go:build linux

package commands

import (
	"os"
	"strings"
	"testing"
)

func TestListProcessModules_Self(t *testing.T) {
	pid := os.Getpid()
	modules, err := listProcessModules(pid)
	if err != nil {
		t.Fatalf("listProcessModules(%d) failed: %v", pid, err)
	}

	if len(modules) == 0 {
		t.Fatal("expected at least 1 module for current process")
	}

	// Every module should have a name and path
	for i, m := range modules {
		if m.Name == "" {
			t.Errorf("module %d: empty name", i)
		}
		if m.Path == "" {
			t.Errorf("module %d: empty path", i)
		}
		if !strings.HasPrefix(m.Path, "/") {
			t.Errorf("module %d: path should be absolute, got %q", i, m.Path)
		}
		if m.BaseAddr == "" {
			t.Errorf("module %d: empty BaseAddr", i)
		}
		if !strings.HasPrefix(m.BaseAddr, "0x") {
			t.Errorf("module %d: BaseAddr should start with 0x, got %q", i, m.BaseAddr)
		}
		if m.Size == 0 {
			t.Errorf("module %d (%s): expected non-zero size", i, m.Name)
		}
	}

	// Should include libc or ld-linux (standard dynamic linker)
	foundLibc := false
	for _, m := range modules {
		if strings.Contains(m.Name, "libc") || strings.Contains(m.Name, "ld-linux") || strings.Contains(m.Name, "ld-musl") {
			foundLibc = true
			break
		}
	}
	if !foundLibc {
		// Log module list for debugging but don't fail — static binaries may not have libc
		t.Logf("Warning: no libc found among %d modules (may be a static binary)", len(modules))
	}
}

func TestListProcessModules_InvalidPID(t *testing.T) {
	_, err := listProcessModules(999999999)
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}

func TestListProcessModules_PID1(t *testing.T) {
	// PID 1 should exist but may not be readable depending on permissions
	modules, err := listProcessModules(1)
	if err != nil {
		// This is expected in many environments (unprivileged)
		t.Skipf("cannot read /proc/1/maps: %v (expected if unprivileged)", err)
	}
	if len(modules) == 0 {
		t.Error("expected at least 1 module for PID 1")
	}
}

func TestListProcessModules_NoDuplicates(t *testing.T) {
	pid := os.Getpid()
	modules, err := listProcessModules(pid)
	if err != nil {
		t.Fatalf("listProcessModules failed: %v", err)
	}

	seen := make(map[string]bool)
	for _, m := range modules {
		if seen[m.Path] {
			t.Errorf("duplicate module path: %s", m.Path)
		}
		seen[m.Path] = true
	}
}

func TestListProcessModules_SizesReasonable(t *testing.T) {
	pid := os.Getpid()
	modules, err := listProcessModules(pid)
	if err != nil {
		t.Fatalf("listProcessModules failed: %v", err)
	}

	for _, m := range modules {
		// Each module mapping should be > 0 and < 1GB (reasonable bounds)
		if m.Size > 1024*1024*1024 {
			t.Errorf("module %s has unreasonable size: %d bytes", m.Name, m.Size)
		}
	}
}
