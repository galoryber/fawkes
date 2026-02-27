package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestVmDetectName(t *testing.T) {
	cmd := &VmDetectCommand{}
	if cmd.Name() != "vm-detect" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "vm-detect")
	}
}

func TestVmDetectDescription(t *testing.T) {
	cmd := &VmDetectCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestVmDetectExecute(t *testing.T) {
	cmd := &VmDetectCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
	if !strings.Contains(result.Output, "VM/Hypervisor Detection") {
		t.Error("Output should contain detection header")
	}
}

func TestVmCheckMAC(t *testing.T) {
	evidence, _ := vmCheckMAC()
	// Should return at least one result
	if len(evidence) == 0 {
		t.Error("vmCheckMAC should return at least one evidence item")
	}
}

func TestVmMACPrefixes(t *testing.T) {
	// Verify known prefixes are present
	knownVMs := []string{"VMware", "VirtualBox", "Hyper-V", "Xen", "QEMU/KVM"}
	found := make(map[string]bool)
	for _, vm := range vmMACPrefixes {
		found[vm] = true
	}
	for _, vm := range knownVMs {
		if !found[vm] {
			t.Errorf("Expected %s in vmMACPrefixes", vm)
		}
	}
}

func TestVmDetectLinux(t *testing.T) {
	evidence, _ := vmDetectLinux()
	// Should return some evidence (DMI checks, etc.)
	if len(evidence) == 0 {
		t.Error("vmDetectLinux should return at least one evidence item")
	}
}

func TestVmDetectOutputFormat(t *testing.T) {
	cmd := &VmDetectCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)

	// Should have table header
	if !strings.Contains(result.Output, "Check") {
		t.Error("Output should contain Check column header")
	}
	if !strings.Contains(result.Output, "Hypervisor") {
		t.Error("Output should contain Hypervisor line")
	}
}
