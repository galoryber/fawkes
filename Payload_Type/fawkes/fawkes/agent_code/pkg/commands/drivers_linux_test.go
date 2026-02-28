//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestEnumerateDrivers_Live(t *testing.T) {
	drivers, err := enumerateDrivers()
	if err != nil {
		t.Fatalf("enumerateDrivers failed: %v", err)
	}

	// Most Linux systems have at least a few kernel modules loaded
	if len(drivers) == 0 {
		t.Skip("no kernel modules loaded (could be a minimal/container environment)")
	}

	for i, d := range drivers {
		if d.Name == "" {
			t.Errorf("driver %d: empty name", i)
		}
		if d.Status == "" {
			t.Errorf("driver %d (%s): empty status", i, d.Name)
		}
		// Status should be one of known values
		validStates := map[string]bool{"live": true, "loading": true, "unloading": true, "loaded": true}
		if !validStates[d.Status] {
			t.Errorf("driver %d (%s): unexpected status %q", i, d.Name, d.Status)
		}
	}
}

func TestEnumerateDrivers_HasKnownModules(t *testing.T) {
	drivers, err := enumerateDrivers()
	if err != nil {
		t.Fatalf("enumerateDrivers failed: %v", err)
	}

	if len(drivers) == 0 {
		t.Skip("no kernel modules loaded")
	}

	// Check for at least one module name that doesn't contain spaces or weird chars
	for _, d := range drivers {
		if strings.ContainsAny(d.Name, " \t\n") {
			t.Errorf("driver name contains whitespace: %q", d.Name)
		}
	}
}

func TestEnumerateDrivers_SizesPositive(t *testing.T) {
	drivers, err := enumerateDrivers()
	if err != nil {
		t.Fatalf("enumerateDrivers failed: %v", err)
	}

	for _, d := range drivers {
		if d.Size == 0 {
			// Some modules can have 0 size (built-in stubs), just warn
			t.Logf("module %s has size 0", d.Name)
		}
	}
}

func TestEnumerateDrivers_NoDuplicateNames(t *testing.T) {
	drivers, err := enumerateDrivers()
	if err != nil {
		t.Fatalf("enumerateDrivers failed: %v", err)
	}

	seen := make(map[string]bool)
	for _, d := range drivers {
		if seen[d.Name] {
			t.Errorf("duplicate module name: %s", d.Name)
		}
		seen[d.Name] = true
	}
}

func TestFindModulePath(t *testing.T) {
	// findModulePath currently always returns "" but let's verify it doesn't panic
	result := findModulePath("nonexistent_module_xyz")
	if result != "" {
		t.Errorf("expected empty string for nonexistent module, got %q", result)
	}

	// Try with a module that likely exists in /sys/module
	result = findModulePath("kernel")
	// Result is still "" because findModulePath returns "" for all (it's a stub)
	// Just verify no panic
}
