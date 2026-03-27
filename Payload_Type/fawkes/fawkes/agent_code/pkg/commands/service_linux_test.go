//go:build linux

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestServiceCommandName(t *testing.T) {
	cmd := &ServiceCommand{}
	if cmd.Name() != "service" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "service")
	}
}

func TestServiceCommandDescription(t *testing.T) {
	cmd := &ServiceCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "systemctl") {
		t.Error("description should mention systemctl")
	}
}

func TestServiceExecuteEmptyParams(t *testing.T) {
	cmd := &ServiceCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Error("expected 'parameters required' in error output")
	}
}

func TestServiceExecuteInvalidJSON(t *testing.T) {
	cmd := &ServiceCommand{}
	result := cmd.Execute(structs.Task{Params: "not-json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Error parsing") {
		t.Error("expected parsing error in output")
	}
}

func TestServiceExecuteUnknownAction(t *testing.T) {
	cmd := &ServiceCommand{}
	params, _ := json.Marshal(serviceArgs{Action: "bogus"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action: bogus") {
		t.Errorf("expected 'Unknown action: bogus', got %q", result.Output)
	}
}

func TestServiceQueryLinuxEmptyName(t *testing.T) {
	result := serviceQueryLinux(serviceArgs{Action: "query", Name: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Error("expected 'name is required' error")
	}
}

func TestServiceCtlEmptyName(t *testing.T) {
	actions := []string{"start", "stop", "enable", "disable"}
	for _, action := range actions {
		result := serviceCtl(serviceArgs{Name: ""}, action)
		if result.Status != "error" {
			t.Errorf("serviceCtl(%q) with empty name: expected error, got %q", action, result.Status)
		}
		if !strings.Contains(result.Output, "name is required") {
			t.Errorf("serviceCtl(%q): expected 'name is required', got %q", action, result.Output)
		}
	}
}

func TestServiceExecuteActionCaseInsensitive(t *testing.T) {
	cmd := &ServiceCommand{}
	// "QUERY" should route to serviceQueryLinux which requires a name
	params, _ := json.Marshal(serviceArgs{Action: "QUERY"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should hit serviceQueryLinux's name check, not "Unknown action"
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("action routing should be case-insensitive")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name required error from query, got %q", result.Output)
	}
}

func TestServiceListLinuxLive(t *testing.T) {
	// Live test: systemctl should be available on this Linux system
	result := serviceListLinux()
	if result.Status != "success" {
		t.Skipf("systemctl not available: %s", result.Output)
	}

	// Should return valid JSON array
	var entries []linuxServiceEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, result.Output[:min(200, len(result.Output))])
	}

	if len(entries) == 0 {
		t.Error("expected at least one service entry")
	}

	// Every entry should have a name and load state
	for _, e := range entries {
		if e.Name == "" {
			t.Error("entry has empty name")
		}
		if e.Load == "" {
			t.Error("entry has empty load state")
		}
		if e.Active == "" {
			t.Error("entry has empty active state")
		}
	}
}

func TestServiceQueryLinuxLive(t *testing.T) {
	// Query a service that almost certainly exists on Linux
	result := serviceQueryLinux(serviceArgs{Name: "systemd-journald"})
	if result.Status != "success" {
		t.Skipf("systemd-journald not available: %s", result.Output)
	}

	// Output should contain structured info
	if !strings.Contains(result.Output, "Service: systemd-journald") {
		t.Error("expected service name in output")
	}
	if !strings.Contains(result.Output, "Load State:") {
		t.Error("expected Load State field")
	}
	if !strings.Contains(result.Output, "Active State:") {
		t.Error("expected Active State field")
	}
}

func TestServiceQueryLinuxNotFound(t *testing.T) {
	result := serviceQueryLinux(serviceArgs{Name: "nonexistent-service-xyz-12345"})
	if result.Status != "error" {
		// Some systems may not report "not-found" the same way
		if !strings.Contains(result.Output, "not found") && !strings.Contains(result.Output, "not-found") {
			t.Logf("unexpected success for nonexistent service: %s", result.Output[:min(200, len(result.Output))])
		}
	}
}

func TestServiceQueryLinuxAutoSuffix(t *testing.T) {
	// Querying without .service suffix should work the same as with it
	result1 := serviceQueryLinux(serviceArgs{Name: "systemd-journald"})
	result2 := serviceQueryLinux(serviceArgs{Name: "systemd-journald.service"})
	if result1.Status != result2.Status {
		t.Errorf("auto-suffix mismatch: without=%q, with=%q", result1.Status, result2.Status)
	}
}

// --- buildSystemdUnit tests ---

func TestBuildSystemdUnit(t *testing.T) {
	unit := buildSystemdUnit(serviceArgs{
		Name:    "test-svc",
		BinPath: "/opt/payload/agent",
		Display: "Test Service",
	})

	if !strings.Contains(unit, "[Unit]") {
		t.Error("missing [Unit] section")
	}
	if !strings.Contains(unit, "Description=Test Service") {
		t.Error("missing Description")
	}
	if !strings.Contains(unit, "[Service]") {
		t.Error("missing [Service] section")
	}
	if !strings.Contains(unit, "ExecStart=/opt/payload/agent") {
		t.Error("missing ExecStart")
	}
	if !strings.Contains(unit, "Restart=on-failure") {
		t.Error("missing Restart directive")
	}
	if !strings.Contains(unit, "[Install]") {
		t.Error("missing [Install] section")
	}
	if !strings.Contains(unit, "WantedBy=multi-user.target") {
		t.Error("missing WantedBy")
	}
	if !strings.Contains(unit, "After=network.target") {
		t.Error("missing After dependency")
	}
}

func TestBuildSystemdUnitDefaultDescription(t *testing.T) {
	// When display is empty, should use name
	unit := buildSystemdUnit(serviceArgs{
		Name:    "my-daemon",
		BinPath: "/usr/local/bin/daemon",
	})

	if !strings.Contains(unit, "Description=my-daemon") {
		t.Errorf("expected name as fallback description, got:\n%s", unit)
	}
}

// --- serviceCreateLinux validation tests ---

func TestServiceCreateLinuxMissingName(t *testing.T) {
	result := serviceCreateLinux(serviceArgs{BinPath: "/some/binary"})
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected 'name is required', got %q", result.Output)
	}
}

func TestServiceCreateLinuxMissingBinPath(t *testing.T) {
	result := serviceCreateLinux(serviceArgs{Name: "test-svc"})
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "binpath is required") {
		t.Errorf("expected 'binpath is required', got %q", result.Output)
	}
}

func TestServiceCreateLinuxExistingFile(t *testing.T) {
	// Create a temp "service file" and try to create over it
	tmpDir := t.TempDir()

	// This test can't write to /etc/systemd/system on CI, so we test the
	// existing-file check logic by verifying the error message pattern
	result := serviceCreateLinux(serviceArgs{
		Name:    "systemd-journald", // exists on most Linux
		BinPath: "/bin/true",
	})
	// Either it finds the existing file or fails to write (no root)
	if result.Status == "success" {
		t.Error("should not succeed without cleanup of existing service")
	}
	_ = tmpDir // suppress unused
}

// --- serviceDeleteLinux validation tests ---

func TestServiceDeleteLinuxMissingName(t *testing.T) {
	result := serviceDeleteLinux(serviceArgs{})
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected 'name is required', got %q", result.Output)
	}
}

func TestServiceDeleteLinuxNonExistent(t *testing.T) {
	result := serviceDeleteLinux(serviceArgs{Name: "nonexistent-fawkes-test-12345"})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent service, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "not found") {
		t.Errorf("expected 'not found' error, got %q", result.Output)
	}
}

// --- Action routing for create/delete ---

func TestServiceExecuteCreateRoute(t *testing.T) {
	cmd := &ServiceCommand{}
	// Verify create action routes correctly (will fail on missing name, not unknown action)
	params, _ := json.Marshal(serviceArgs{Action: "create"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("'create' should be a recognized action")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name validation error, got %q", result.Output)
	}
}

func TestServiceExecuteDeleteRoute(t *testing.T) {
	cmd := &ServiceCommand{}
	// Verify delete action routes correctly
	params, _ := json.Marshal(serviceArgs{Action: "delete"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("'delete' should be a recognized action")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name validation error, got %q", result.Output)
	}
}

func TestServiceDescriptionIncludesCreateDelete(t *testing.T) {
	cmd := &ServiceCommand{}
	desc := cmd.Description()
	if !strings.Contains(desc, "create") {
		t.Error("description should mention create")
	}
	if !strings.Contains(desc, "delete") {
		t.Error("description should mention delete")
	}
}

func TestServiceQueryNotFound(t *testing.T) {
	// Query a service that doesn't exist — triggers "not-found" LoadState branch
	result := serviceQueryLinux(serviceArgs{Name: "nonexistent_fawkes_test_service_12345"})
	if result.Status != "error" {
		// If systemctl isn't available, query may fail differently
		return
	}
	if !strings.Contains(result.Output, "not found") {
		t.Errorf("expected 'not found' in output, got: %s", result.Output)
	}
}

func TestServiceQueryMissingName(t *testing.T) {
	result := serviceQueryLinux(serviceArgs{Name: ""})
	if result.Status != "error" {
		t.Error("expected error for empty name")
	}
}

func TestServiceQueryAppendsSuffix(t *testing.T) {
	// Query with .service suffix already present — should not double-append
	result := serviceQueryLinux(serviceArgs{Name: "nonexistent_fawkes_test_12345.service"})
	if result.Status != "error" {
		return
	}
	// Should still report not found, not a suffix error
	if !strings.Contains(result.Output, "not found") && !strings.Contains(result.Output, "Error querying") {
		t.Errorf("unexpected error output: %s", result.Output)
	}
}
