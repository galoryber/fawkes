//go:build windows
// +build windows

package commands

import (
	"testing"
	"unsafe"
)

func TestScanForGUID_Found(t *testing.T) {
	// scanForGUID looks for pattern at offset i+4 (GUID is after uint32 Length field).
	// Place pattern at byte 24 in the buffer, so the struct starts at byte 20.
	pattern := []byte{0x70, 0x07, 0xF7, 0x18, 0x64, 0x8E, 0xCF, 0x11}
	data := make([]byte, 256)
	copy(data[24:], pattern)

	base := uintptr(unsafe.Pointer(&data[0]))
	addr, err := scanForGUID(base, uintptr(len(data)), pattern)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := base + 20
	if addr != expected {
		t.Errorf("expected address 0x%x, got 0x%x", expected, addr)
	}
}

func TestScanForGUID_NotFound(t *testing.T) {
	pattern := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	data := make([]byte, 128) // all zeros

	base := uintptr(unsafe.Pointer(&data[0]))
	_, err := scanForGUID(base, uintptr(len(data)), pattern)
	if err == nil {
		t.Fatal("expected error for missing pattern, got nil")
	}
}

func TestScanForGUID_AtStart(t *testing.T) {
	// Pattern at offset 4 means struct at offset 0
	pattern := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	data := make([]byte, 64)
	copy(data[4:], pattern)

	base := uintptr(unsafe.Pointer(&data[0]))
	addr, err := scanForGUID(base, uintptr(len(data)), pattern)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != base {
		t.Errorf("expected address at base 0x%x, got 0x%x", base, addr)
	}
}

func TestScanForGUID_FirstMatchReturned(t *testing.T) {
	// Two copies of pattern — should return the first match
	pattern := []byte{0x11, 0x22, 0x33, 0x44}
	data := make([]byte, 128)
	copy(data[4:], pattern)   // struct at offset 0
	copy(data[64:], pattern)  // struct at offset 60

	base := uintptr(unsafe.Pointer(&data[0]))
	addr, err := scanForGUID(base, uintptr(len(data)), pattern)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != base {
		t.Errorf("expected first match at base 0x%x, got 0x%x", base, addr)
	}
}

func TestScanForGUID_TooSmall(t *testing.T) {
	pattern := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	data := make([]byte, 8) // too small to contain 4-byte prefix + 8-byte pattern

	base := uintptr(unsafe.Pointer(&data[0]))
	_, err := scanForGUID(base, uintptr(len(data)), pattern)
	if err == nil {
		t.Fatal("expected error for buffer too small, got nil")
	}
}

func TestBuildCraftedOBJREF_ContainsIPID(t *testing.T) {
	oxid := [8]byte{}
	oid := [8]byte{}
	ipid := [16]byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}

	result := buildCraftedOBJREF(oxid, oid, ipid)

	// IPID at offset 48 (after sig+flags+IID+stdobjflags+pubRefs+OXID+OID)
	ipidOffset := 24 + 4 + 4 + 8 + 8 // = 48
	if len(result) < ipidOffset+16 {
		t.Fatalf("OBJREF too short: %d bytes", len(result))
	}
	for i := 0; i < 16; i++ {
		if result[ipidOffset+i] != ipid[i] {
			t.Errorf("IPID byte %d: expected 0x%02X, got 0x%02X", i, ipid[i], result[ipidOffset+i])
		}
	}
}

func TestBuildCraftedOBJREF_ContainsTCPBindings(t *testing.T) {
	result := buildCraftedOBJREF([8]byte{}, [8]byte{}, [16]byte{})

	// After the STDOBJREF (64 bytes), the DUALSTRINGARRAY starts
	// Check that the TCP tower ID (0x0007) appears in the bindings
	dsaStart := 64 // sig(4)+flags(4)+IID(16)+stdobjflags(4)+pubRefs(4)+OXID(8)+OID(8)+IPID(16)
	if len(result) < dsaStart+6 {
		t.Fatalf("OBJREF too short for DSA: %d bytes", len(result))
	}
	// DSA header is 4 bytes, then first string binding tower ID
	towerOffset := dsaStart + 4
	towerID := uint16(result[towerOffset]) | uint16(result[towerOffset+1])<<8
	if towerID != 0x0007 {
		t.Errorf("expected TCP tower ID 0x0007, got 0x%04X", towerID)
	}
}

func TestBuildTCPDualStringArray_Contains127001(t *testing.T) {
	result := buildTCPDualStringArray()

	// Check that "127.0.0.1" appears as UTF-16LE in the output
	target := "127.0.0.1"
	found := false
	for i := 4; i+len(target)*2 <= len(result); i += 2 {
		match := true
		for j, ch := range target {
			if i+j*2+1 >= len(result) || result[i+j*2] != byte(ch) || result[i+j*2+1] != 0 {
				match = false
				break
			}
		}
		if match {
			found = true
			break
		}
	}
	if !found {
		t.Error("127.0.0.1 not found as UTF-16LE in TCP DSA")
	}
}

func TestPotatoMin_Edge(t *testing.T) {
	if potatoMin(0, 1) != 0 {
		t.Error("min(0,1) should be 0")
	}
	if potatoMin(1<<31-1, 1<<31-1) != 1<<31-1 {
		t.Error("min(maxInt31, maxInt31) should be maxInt31")
	}
}
