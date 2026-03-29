//go:build windows

package commands

import (
	"testing"
	"unsafe"
)

func TestOrcbGUID_Value(t *testing.T) {
	// ORCB RPC interface GUID: 18f70770-8e64-11cf-9af1-0020af6e72f4
	// Verify Data1 (little-endian): 0x18F70770
	if orcbGUID[0] != 0x70 || orcbGUID[1] != 0x07 || orcbGUID[2] != 0xF7 || orcbGUID[3] != 0x18 {
		t.Errorf("Data1 mismatch: got %x %x %x %x", orcbGUID[0], orcbGUID[1], orcbGUID[2], orcbGUID[3])
	}
	// Verify Data2 (little-endian): 0x8E64
	if orcbGUID[4] != 0x64 || orcbGUID[5] != 0x8E {
		t.Errorf("Data2 mismatch: got %x %x", orcbGUID[4], orcbGUID[5])
	}
	// Verify Data3 (little-endian): 0x11CF
	if orcbGUID[6] != 0xCF || orcbGUID[7] != 0x11 {
		t.Errorf("Data3 mismatch: got %x %x", orcbGUID[6], orcbGUID[7])
	}
}

func TestObjrefSignature(t *testing.T) {
	// "MEOW" in little-endian = 0x574f454d
	if objrefSignature != 0x574f454d {
		t.Errorf("objrefSignature = 0x%x, want 0x574f454d", objrefSignature)
	}
}

func TestObjrefStandard(t *testing.T) {
	if objrefStandard != 0x00000001 {
		t.Errorf("objrefStandard = 0x%x, want 0x1", objrefStandard)
	}
}

func TestIIDIUnknown(t *testing.T) {
	// IID_IUnknown: 00000000-0000-0000-C000-000000000046
	expected := [16]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	}
	if iidIUnknown != expected {
		t.Errorf("IID_IUnknown mismatch: got %x, want %x", iidIUnknown, expected)
	}
}

func TestPotatoState_InitialValues(t *testing.T) {
	var state potatoState
	if state.tokenCaptured {
		t.Error("tokenCaptured should be false initially")
	}
	if state.hookCalled {
		t.Error("hookCalled should be false initially")
	}
	if state.pipeName != "" {
		t.Error("pipeName should be empty initially")
	}
	if state.hookError != "" {
		t.Error("hookError should be empty initially")
	}
	if state.paramCount != 0 {
		t.Error("paramCount should be 0 initially")
	}
}

func TestRpcServerInterface_Size(t *testing.T) {
	// Verify the struct size matches expected layout
	size := unsafe.Sizeof(rpcServerInterface{})
	// 4 + 20 + 20 + ptr + 4 + ptr + ptr + ptr + 4 = varies by arch
	if size == 0 {
		t.Error("rpcServerInterface size should not be 0")
	}
}

func TestProcessMitigationPolicyConstants(t *testing.T) {
	// Verify policy type constants match Windows definitions
	if ProcessDEPPolicy != 0 {
		t.Errorf("ProcessDEPPolicy = %d, want 0", ProcessDEPPolicy)
	}
	if ProcessASLRPolicy != 1 {
		t.Errorf("ProcessASLRPolicy = %d, want 1", ProcessASLRPolicy)
	}
	if ProcessDynamicCodePolicy != 2 {
		t.Errorf("ProcessDynamicCodePolicy = %d, want 2", ProcessDynamicCodePolicy)
	}
	if ProcessSignaturePolicy != 8 {
		t.Errorf("ProcessSignaturePolicy = %d, want 8", ProcessSignaturePolicy)
	}
	if ProcessImageLoadPolicy != 10 {
		t.Errorf("ProcessImageLoadPolicy = %d, want 10", ProcessImageLoadPolicy)
	}
}
