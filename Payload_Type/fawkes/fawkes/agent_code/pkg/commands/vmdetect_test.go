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

// --- Sandbox Detection Tests ---

func TestSandboxCheckCPUCount(t *testing.T) {
	check := sandboxCheckCPUCount()
	if check.Name != "CPU Count" {
		t.Errorf("expected 'CPU Count', got %q", check.Name)
	}
	if check.Category != "hardware" {
		t.Errorf("expected category 'hardware', got %q", check.Category)
	}
	// On any real machine, CPUs should be a positive number
	if check.Details == "" {
		t.Error("details should not be empty")
	}
}

func TestSandboxCheckHostname(t *testing.T) {
	check := sandboxCheckHostname()
	if check.Name != "Hostname" {
		t.Errorf("expected 'Hostname', got %q", check.Name)
	}
	if check.Details == "" {
		t.Error("hostname should be populated")
	}
}

func TestSandboxCheckUsername(t *testing.T) {
	check := sandboxCheckUsername()
	if check.Name != "Username" {
		t.Errorf("expected 'Username', got %q", check.Name)
	}
}

func TestSandboxCheckSleepDrift(t *testing.T) {
	check := sandboxCheckSleepDrift()
	if check.Name != "Sleep Timing" {
		t.Errorf("expected 'Sleep Timing', got %q", check.Name)
	}
	if check.Category != "timing" {
		t.Errorf("expected category 'timing', got %q", check.Category)
	}
	// On a normal machine, sleep should be reasonably accurate
	if check.Details == "" {
		t.Error("details should include timing info")
	}
}

func TestSandboxCheckProcessCount(t *testing.T) {
	check := sandboxCheckProcessCount()
	if check.Name != "Process Count" {
		t.Errorf("expected 'Process Count', got %q", check.Name)
	}
	// On a real machine with a full OS, we should have processes
	if check.Details == "" {
		t.Error("details should be populated")
	}
}

func TestSandboxCheckUptime(t *testing.T) {
	check := sandboxCheckUptime()
	if check.Name != "System Uptime" {
		t.Errorf("expected 'System Uptime', got %q", check.Name)
	}
	if check.Category != "timing" {
		t.Errorf("expected category 'timing', got %q", check.Category)
	}
}

func TestSandboxCheckRAM(t *testing.T) {
	check := sandboxCheckRAM()
	if check.Name != "Total RAM" {
		t.Errorf("expected 'Total RAM', got %q", check.Name)
	}
}

func TestSandboxCheckDisk(t *testing.T) {
	check := sandboxCheckDisk()
	if check.Name != "Disk Size" {
		t.Errorf("expected 'Disk Size', got %q", check.Name)
	}
}

func TestVmSandboxDetect(t *testing.T) {
	result := vmSandboxDetect()
	if result.TotalScore < 0 || result.TotalScore > 100 {
		t.Errorf("score should be 0-100, got %d", result.TotalScore)
	}
	if result.Verdict == "" {
		t.Error("verdict should not be empty")
	}
	validVerdicts := map[string]bool{"clean": true, "suspicious": true, "likely_sandbox": true, "sandbox": true}
	if !validVerdicts[result.Verdict] {
		t.Errorf("invalid verdict: %q", result.Verdict)
	}
	if len(result.Checks) == 0 {
		t.Error("should have at least one check")
	}
}

func TestFormatSandboxResult(t *testing.T) {
	result := sandboxResult{
		TotalScore: 25,
		Verdict:    "suspicious",
		Checks: []sandboxCheck{
			{Name: "Test", Category: "test", Score: 25, Details: "test details"},
		},
	}
	output := formatSandboxResult(result)
	if output == "" {
		t.Error("output should not be empty")
	}
	if !strings.Contains(output, "suspicious") {
		t.Error("output should contain verdict")
	}
	if !strings.Contains(output, "25") {
		t.Error("output should contain score")
	}
}

func TestIsNumericString(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123", true},
		{"0", true},
		{"abc", false},
		{"12a3", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isNumericString(tt.input)
		if got != tt.want {
			t.Errorf("isNumericString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestVmDetectSandboxAction(t *testing.T) {
	c := &VmDetectCommand{}
	params := `{"action":"sandbox"}`
	result := c.Execute(structs.Task{Params: params})
	if result.Status != "success" {
		t.Errorf("sandbox action failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "total_score") {
		t.Error("output should contain JSON with total_score")
	}
}

func TestVmDetectDefaultAction(t *testing.T) {
	c := &VmDetectCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("default action failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Hypervisor") {
		t.Error("output should contain VM detection results")
	}
}

func TestVmDetectInvalidAction(t *testing.T) {
	c := &VmDetectCommand{}
	result := c.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %s", result.Status)
	}
}
