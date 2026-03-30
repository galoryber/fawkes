//go:build windows

package commands

import (
	"testing"
	"unsafe"
)

func TestProcessMitigationPolicy_Constants(t *testing.T) {
	// Verify policy type constants match Windows SDK values
	tests := []struct {
		name  string
		value int
		want  int
	}{
		{"DEP", ProcessDEPPolicy, 0},
		{"ASLR", ProcessASLRPolicy, 1},
		{"DynamicCode", ProcessDynamicCodePolicy, 2},
		{"StrictHandle", ProcessStrictHandleCheckPolicy, 3},
		{"SystemCallDisable", ProcessSystemCallDisablePolicy, 4},
		{"ExtensionPoint", ProcessExtensionPointDisablePolicy, 6},
		{"CFG", ProcessControlFlowGuardPolicy, 7},
		{"Signature", ProcessSignaturePolicy, 8},
		{"FontDisable", ProcessFontDisablePolicy, 9},
		{"ImageLoad", ProcessImageLoadPolicy, 10},
		{"ChildProcess", ProcessChildProcessPolicy, 13},
		{"ShadowStack", ProcessUserShadowStackPolicy, 15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

func TestPolicyStructSizes(t *testing.T) {
	// DEP policy has Flags + Permanent = 8 bytes
	depSize := unsafe.Sizeof(processMitigationDEPPolicy{})
	if depSize != 8 {
		t.Errorf("DEP policy size = %d, want 8", depSize)
	}

	// Single-flag policies should be 4 bytes
	aslrSize := unsafe.Sizeof(processMitigationASLRPolicy{})
	if aslrSize != 4 {
		t.Errorf("ASLR policy size = %d, want 4", aslrSize)
	}

	dynSize := unsafe.Sizeof(processMitigationDynamicCodePolicy{})
	if dynSize != 4 {
		t.Errorf("DynamicCode policy size = %d, want 4", dynSize)
	}

	handleSize := unsafe.Sizeof(processMitigationStrictHandlePolicy{})
	if handleSize != 4 {
		t.Errorf("StrictHandle policy size = %d, want 4", handleSize)
	}

	syscallSize := unsafe.Sizeof(processMitigationSystemCallDisablePolicy{})
	if syscallSize != 4 {
		t.Errorf("SystemCallDisable policy size = %d, want 4", syscallSize)
	}
}

func TestDEPPolicyBitFlags(t *testing.T) {
	policy := processMitigationDEPPolicy{
		Flags:     0x1, // Enable bit
		Permanent: 1,
	}
	if policy.Flags&0x1 == 0 {
		t.Error("DEP enable bit not set")
	}
	if policy.Permanent != 1 {
		t.Error("Permanent should be 1")
	}
}
