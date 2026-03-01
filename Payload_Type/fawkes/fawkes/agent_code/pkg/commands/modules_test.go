package commands

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestModulesCommand_Name(t *testing.T) {
	cmd := &ModulesCommand{}
	if cmd.Name() != "modules" {
		t.Errorf("expected 'modules', got %q", cmd.Name())
	}
}

func TestModulesCommand_SelfModules(t *testing.T) {
	// List modules for our own process — should always work
	modules, err := listProcessModules(os.Getpid())
	if err != nil {
		t.Fatalf("listProcessModules(self) failed: %v", err)
	}

	if len(modules) == 0 {
		t.Fatal("expected at least 1 module for self")
	}

	// Verify all modules have names and paths
	for _, m := range modules {
		if m.Name == "" {
			t.Error("module has empty name")
		}
		if m.Path == "" {
			t.Error("module has empty path")
		}
		if m.BaseAddr == "" {
			t.Error("module has empty base address")
		}
	}

	t.Logf("Found %d modules for PID %d", len(modules), os.Getpid())
	for _, m := range modules {
		t.Logf("  %s %s (%s) %s", m.BaseAddr, formatModuleSize(m.Size), m.Name, m.Path)
	}
}

func TestModulesCommand_Execute(t *testing.T) {
	cmd := &ModulesCommand{}

	// Test with no params (defaults to self)
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Fatalf("Execute with no params failed: %s", result.Output)
	}
	var modules []ModuleInfo
	if err := json.Unmarshal([]byte(result.Output), &modules); err != nil {
		t.Errorf("output should be valid JSON array: %v", err)
	}
	if len(modules) == 0 {
		t.Error("expected at least one module")
	}
}

func TestModulesCommand_ExecuteWithPID(t *testing.T) {
	cmd := &ModulesCommand{}

	// Test with explicit self PID
	params, _ := json.Marshal(modulesArgs{PID: os.Getpid()})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Execute with self PID failed: %s", result.Output)
	}
}

func TestModulesCommand_InvalidPID(t *testing.T) {
	cmd := &ModulesCommand{}

	// Test with a PID that doesn't exist
	params, _ := json.Marshal(modulesArgs{PID: 99999999})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for invalid PID")
	}
}

func TestModulesCommand_InvalidJSON(t *testing.T) {
	cmd := &ModulesCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestFormatModuleSize(t *testing.T) {
	tests := []struct {
		size     uint64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{4096, "4.0 KB"},
		{1048576, "1.0 MB"},
		{10485760, "10.0 MB"},
	}

	for _, tt := range tests {
		result := formatModuleSize(tt.size)
		if result != tt.expected {
			t.Errorf("formatModuleSize(%d) = %q, want %q", tt.size, result, tt.expected)
		}
	}
}

func TestModulesCommand_WindowsDLLs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	modules, err := listProcessModules(os.Getpid())
	if err != nil {
		t.Fatalf("listProcessModules failed: %v", err)
	}

	// On Windows, every process loads at minimum ntdll.dll and kernel32.dll
	foundNtdll := false
	foundKernel32 := false
	for _, m := range modules {
		nameLower := strings.ToLower(m.Name)
		if nameLower == "ntdll.dll" {
			foundNtdll = true
		}
		if nameLower == "kernel32.dll" {
			foundKernel32 = true
		}
	}

	if !foundNtdll {
		t.Error("expected ntdll.dll in module list")
	}
	if !foundKernel32 {
		t.Error("expected kernel32.dll in module list")
	}
}

func TestModulesCommand_LinuxLibraries(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	modules, err := listProcessModules(os.Getpid())
	if err != nil {
		t.Fatalf("listProcessModules failed: %v", err)
	}

	// On Linux, at minimum the binary itself should be in the maps
	if len(modules) == 0 {
		t.Error("expected at least 1 module on Linux")
	}

	// Verify addresses are hex-formatted
	for _, m := range modules {
		if !strings.HasPrefix(m.BaseAddr, "0x") {
			t.Errorf("expected hex address, got %q", m.BaseAddr)
		}
	}
}
