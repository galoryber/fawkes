//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestHookFlagOffset_Consistency(t *testing.T) {
	// hookFlagOffset must be within the first page (4096 bytes) and
	// must not overlap with the diagnostic parameter area
	if hookFlagOffset >= 4096 {
		t.Errorf("hookFlagOffset %d exceeds page size", hookFlagOffset)
	}
	if hookFlagOffset >= diagParamBase {
		t.Errorf("hookFlagOffset %d overlaps with diagParamBase %d", hookFlagOffset, diagParamBase)
	}
}

func TestDiagParamBase_Layout(t *testing.T) {
	// 5 saved params × 8 bytes each = 40 bytes from diagParamBase
	endOfDiag := diagParamBase + 5*8
	if endOfDiag > 4096 {
		t.Errorf("diagnostic params extend beyond page: end=%d", endOfDiag)
	}
	if diagParamBase <= hookFlagOffset {
		t.Errorf("diagParamBase %d should be after hookFlagOffset %d", diagParamBase, hookFlagOffset)
	}
}

func TestBuildPipeDSA_EndpointCount(t *testing.T) {
	result := buildPipeDSA("testpipe")
	if len(result) < 4 {
		t.Fatalf("DSA too short: %d bytes", len(result))
	}

	// The DSA should contain exactly 2 endpoint strings (ncacn_np + ncacn_ip_tcp)
	// Scan for null-null terminator pairs in the string binding section
	secOffset := int(result[2]) | int(result[3])<<8
	if secOffset < 2 {
		t.Fatalf("unexpected security offset: %d", secOffset)
	}

	// Count string bindings by counting null terminators before secOffset
	nullCount := 0
	for i := 4; i+1 < 4+secOffset*2; i += 2 {
		if result[i] == 0 && result[i+1] == 0 {
			nullCount++
		}
	}
	// 2 endpoints + 1 end-of-bindings marker = 3 null terminators
	if nullCount < 3 {
		t.Errorf("expected at least 3 null terminators (2 endpoints + end marker), got %d", nullCount)
	}
}

func TestAllocateDSAOnHeap(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	addr, err := allocateDSAOnHeap(data)
	if err != nil {
		t.Fatalf("allocateDSAOnHeap failed: %v", err)
	}
	if addr == 0 {
		t.Fatal("allocateDSAOnHeap returned null address")
	}
	// Clean up: reset global state
	potatoGlobal.dsaHeapBuf = 0
}

func TestBuildNativeHook_ParamCounts(t *testing.T) {
	// Allocate a dummy DSA buffer on heap for the hook to reference
	dummyDSA := []byte{0x00, 0x00, 0x00, 0x00}
	dsaAddr, err := allocateDSAOnHeap(dummyDSA)
	if err != nil {
		t.Fatalf("allocateDSAOnHeap: %v", err)
	}
	defer func() { potatoGlobal.dsaHeapBuf = 0 }()

	// Test various valid param counts (4-8)
	for _, count := range []int{4, 5, 6, 7, 8} {
		hookAddr, err := buildNativeHook(count, dsaAddr)
		if err != nil {
			t.Errorf("buildNativeHook(paramCount=%d) failed: %v", count, err)
			continue
		}
		if hookAddr == 0 {
			t.Errorf("buildNativeHook(paramCount=%d) returned null", count)
		}
		// Clean up the allocated page
		if potatoGlobal.shellcodePage != 0 {
			potatoGlobal.shellcodePage = 0
		}
	}
}
