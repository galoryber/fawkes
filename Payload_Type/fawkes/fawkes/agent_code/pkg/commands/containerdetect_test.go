package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestContainerDetectName(t *testing.T) {
	cmd := &ContainerDetectCommand{}
	if cmd.Name() != "container-detect" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "container-detect")
	}
}

func TestContainerDetectDescription(t *testing.T) {
	cmd := &ContainerDetectCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestContainerDetectExecute(t *testing.T) {
	cmd := &ContainerDetectCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
	if !strings.Contains(result.Output, "Container/Environment Detection") {
		t.Error("Output should contain detection header")
	}
}

func TestContainerDetectLinux(t *testing.T) {
	evidence, detected := containerDetectLinux()
	// Should return some evidence regardless
	if len(evidence) == 0 {
		t.Error("Should return at least one piece of evidence")
	}
	// detected should be a string (possibly "none")
	_ = detected
}

func TestContainerDetectOutputFormat(t *testing.T) {
	cmd := &ContainerDetectCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)

	// Should have table header
	if !strings.Contains(result.Output, "Check") && !strings.Contains(result.Output, "Result") {
		t.Error("Output should contain table headers")
	}
}

func TestParseDangerousCaps_AllCaps(t *testing.T) {
	// Full capabilities (all bits set)
	caps := parseDangerousCaps("000001ffffffffff")
	if len(caps) == 0 {
		t.Error("Full caps should include dangerous capabilities")
	}
	found := make(map[string]bool)
	for _, c := range caps {
		found[c] = true
	}
	for _, expected := range []string{"CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE"} {
		if !found[expected] {
			t.Errorf("Expected %s in dangerous caps, got %v", expected, caps)
		}
	}
}

func TestParseDangerousCaps_NoCaps(t *testing.T) {
	caps := parseDangerousCaps("0000000000000000")
	if len(caps) != 0 {
		t.Errorf("Zero caps should return empty, got %v", caps)
	}
}

func TestParseDangerousCaps_OnlySysAdmin(t *testing.T) {
	// CAP_SYS_ADMIN is bit 21 = 0x200000
	caps := parseDangerousCaps("0000000000200000")
	if len(caps) != 1 || caps[0] != "CAP_SYS_ADMIN" {
		t.Errorf("Expected [CAP_SYS_ADMIN], got %v", caps)
	}
}

func TestParseDangerousCaps_OnlySysModule(t *testing.T) {
	// CAP_SYS_MODULE is bit 16 = 0x10000
	caps := parseDangerousCaps("0000000000010000")
	if len(caps) != 1 || caps[0] != "CAP_SYS_MODULE" {
		t.Errorf("Expected [CAP_SYS_MODULE], got %v", caps)
	}
}

func TestIdentifyDangerousCaps(t *testing.T) {
	status := "Name:\ttest\nCapEff:\t000001ffffffffff\nSeccomp:\t0\n"
	caps := identifyDangerousCaps(status)
	if len(caps) == 0 {
		t.Error("Should identify dangerous caps from status content")
	}
}

func TestIdentifyDangerousCaps_NoCapsLine(t *testing.T) {
	status := "Name:\ttest\nSeccomp:\t0\n"
	caps := identifyDangerousCaps(status)
	if caps != nil {
		t.Errorf("Should return nil when no CapEff line, got %v", caps)
	}
}

func TestParseSeccompStatus(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   string
	}{
		{"disabled", "Seccomp:\t0\n", "disabled (no restrictions)"},
		{"strict", "Seccomp:\t1\n", "strict mode"},
		{"filter", "Seccomp:\t2\n", "filter mode (syscall filtering active)"},
		{"missing", "Name:\ttest\n", ""},
		{"with context", "Name:\ttest\nSeccomp:\t2\nCapEff:\t0\n", "filter mode (syscall filtering active)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSeccompStatus(tt.status)
			if got != tt.want {
				t.Errorf("parseSeccompStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}


func TestDangerousCapBitsConsistency(t *testing.T) {
	// Ensure all dangerous caps have valid bit positions
	for bit, name := range dangerousCapBits {
		if bit < 0 || bit > 63 {
			t.Errorf("Invalid bit position %d for %s", bit, name)
		}
		if !strings.HasPrefix(name, "CAP_") {
			t.Errorf("Capability name %q should start with CAP_", name)
		}
	}
}
