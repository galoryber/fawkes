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

func TestClassifyHypervisorType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"xen", "Xen"},
		{"Xen", "Xen"},
		{"kvm", "KVM"},
		{"KVM", "KVM"},
		{"custom", "custom"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := classifyHypervisorType(tt.input); got != tt.want {
			t.Errorf("classifyHypervisorType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestClassifyCloudBoard(t *testing.T) {
	tests := []struct {
		name  string
		board string
		want  string
	}{
		{"GCP", "Google Compute Engine", "GCP"},
		{"GCP lowercase", "google compute engine", "GCP"},
		{"AWS EC2", "Amazon EC2", "AWS EC2"},
		{"Azure VM", "Virtual Machine", ""},
		{"physical", "ProLiant DL380", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyCloudBoard(tt.board); got != tt.want {
				t.Errorf("classifyCloudBoard(%q) = %q, want %q", tt.board, got, tt.want)
			}
		})
	}
}

func TestClassifyVMProcess(t *testing.T) {
	tests := []struct {
		proc string
		want string
	}{
		{"vmtoolsd", "VMware"},
		{"VBoxService", "VirtualBox"},
		{"VBoxClient", "VirtualBox"},
		{"qemu-ga", "QEMU/KVM"},
		{"spice-vdagent", "QEMU/KVM"},
		{"hv_kvp_daemon", "Hyper-V"},
		{"hv_vss_daemon", "Hyper-V"},
		{"xe-daemon", "Xen"},
		{"prl_tools_service", "Parallels"},
		{"sshd", ""},
		{"bash", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := classifyVMProcess(tt.proc); got != tt.want {
			t.Errorf("classifyVMProcess(%q) = %q, want %q", tt.proc, got, tt.want)
		}
	}
}

func TestVmGuestProcessesConsistency(t *testing.T) {
	// Ensure all entries in vmGuestProcesses map to known VM types
	knownVMs := map[string]bool{
		"VMware": true, "VirtualBox": true, "QEMU/KVM": true,
		"Hyper-V": true, "Xen": true, "Parallels": true,
	}
	for proc, vm := range vmGuestProcesses {
		if !knownVMs[vm] {
			t.Errorf("vmGuestProcesses[%q] = %q, not a known VM type", proc, vm)
		}
	}
}

func TestVmDetectLinuxProcesses(t *testing.T) {
	evidence, _ := vmDetectLinuxProcesses()
	// Should return at least one result (either found processes or "clean" message)
	if len(evidence) == 0 {
		t.Error("vmDetectLinuxProcesses should return at least one evidence item")
	}
}
