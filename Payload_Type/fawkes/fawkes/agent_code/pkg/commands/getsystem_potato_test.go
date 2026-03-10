//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"testing"
)

func TestUtf16Encode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []uint16
	}{
		{"empty string", "", nil},
		{"ascii", "ABC", []uint16{0x41, 0x42, 0x43}},
		{"pipe path", "localhost", []uint16{'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't'}},
		{"single char", "A", []uint16{0x41}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf16Encode(tt.input)
			if tt.input == "" {
				// Empty string may produce empty or nil slice
				if len(result) != 0 {
					t.Errorf("expected empty result for empty input, got length %d", len(result))
				}
				return
			}
			if len(result) != len(tt.expected) {
				t.Errorf("length mismatch: expected %d, got %d", len(tt.expected), len(result))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("index %d: expected 0x%04X, got 0x%04X", i, tt.expected[i], result[i])
				}
			}
		})
	}
}

func TestUtf16EncodeNoTrailingNull(t *testing.T) {
	result := utf16Encode("test")
	if len(result) > 0 && result[len(result)-1] == 0 {
		t.Error("utf16Encode should strip trailing null terminator")
	}
}

func TestPotatoMin(t *testing.T) {
	tests := []struct {
		a, b     int
		expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{0, 0, 0},
		{-1, 1, -1},
		{100, 100, 100},
		{-5, -3, -5},
	}

	for _, tt := range tests {
		result := potatoMin(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("potatoMin(%d, %d): expected %d, got %d", tt.a, tt.b, tt.expected, result)
		}
	}
}

func TestBuildPipeDSA_Structure(t *testing.T) {
	result := buildPipeDSA("testpipe")

	// Result should be at least 4 bytes (header)
	if len(result) < 4 {
		t.Fatalf("buildPipeDSA result too short: %d bytes", len(result))
	}

	// First 2 bytes: wNumEntries (uint16 LE)
	numEntries := binary.LittleEndian.Uint16(result[0:2])
	if numEntries == 0 {
		t.Error("wNumEntries should be non-zero")
	}

	// Second 2 bytes: wSecurityOffset (uint16 LE)
	secOffset := binary.LittleEndian.Uint16(result[2:4])
	if secOffset == 0 {
		t.Error("wSecurityOffset should be non-zero")
	}

	// Security offset should be less than total entries
	if secOffset >= numEntries {
		t.Errorf("security offset (%d) should be less than num entries (%d)", secOffset, numEntries)
	}

	// Total size should match: 4 + numEntries*2
	expectedLen := 4 + int(numEntries)*2
	if len(result) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(result))
	}
}

func TestBuildPipeDSA_ContainsPipeName(t *testing.T) {
	pipeName := "mypipe123"
	result := buildPipeDSA(pipeName)

	// Scan through UTF-16LE data for the pipe name
	found := false
	for i := 4; i+len(pipeName)*2 <= len(result); i += 2 {
		match := true
		for j, ch := range pipeName {
			if i+j*2+1 >= len(result) {
				match = false
				break
			}
			if result[i+j*2] != byte(ch) || result[i+j*2+1] != 0 {
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
		t.Errorf("pipe name %q not found in DSA output", pipeName)
	}
}

func TestBuildPipeDSA_DifferentPipeNames(t *testing.T) {
	r1 := buildPipeDSA("pipe_alpha")
	r2 := buildPipeDSA("pipe_beta")

	// Different pipe names should produce different DSA outputs
	if len(r1) == len(r2) {
		same := true
		for i := range r1 {
			if r1[i] != r2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("different pipe names should produce different DSA outputs")
		}
	}
}

func TestBuildTCPDualStringArray_Structure(t *testing.T) {
	result := buildTCPDualStringArray()

	// Minimum size: 4 bytes header + some string binding + security binding
	if len(result) < 8 {
		t.Fatalf("result too short: %d bytes", len(result))
	}

	// First 2 bytes: total entries count
	totalEntries := binary.LittleEndian.Uint16(result[0:2])
	if totalEntries == 0 {
		t.Error("total entries should be non-zero")
	}

	// Second 2 bytes: security offset (where string bindings end)
	secOffset := binary.LittleEndian.Uint16(result[2:4])
	if secOffset == 0 {
		t.Error("security offset should be non-zero")
	}

	// Total length should be 4 + totalEntries*2
	expectedLen := 4 + int(totalEntries)*2
	if len(result) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(result))
	}

	// First string binding should start with tower ID 0x0007 (ncacn_ip_tcp)
	if len(result) >= 6 {
		towerID := binary.LittleEndian.Uint16(result[4:6])
		if towerID != 0x0007 {
			t.Errorf("expected tower ID 0x0007 (ncacn_ip_tcp), got 0x%04X", towerID)
		}
	}
}

func TestBuildCraftedOBJREF_Signature(t *testing.T) {
	oxid := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	oid := [8]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	ipid := [16]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30}

	result := buildCraftedOBJREF(oxid, oid, ipid)

	// Minimum size check
	if len(result) < 48 {
		t.Fatalf("OBJREF too short: %d bytes", len(result))
	}

	// First 4 bytes should be "MEOW" signature (0x574f454d LE)
	sig := binary.LittleEndian.Uint32(result[0:4])
	if sig != 0x574f454d {
		t.Errorf("expected MEOW signature (0x574f454d), got 0x%08X", sig)
	}

	// Bytes 4-7: OBJREF_STANDARD flag (0x00000001)
	flags := binary.LittleEndian.Uint32(result[4:8])
	if flags != 0x00000001 {
		t.Errorf("expected OBJREF_STANDARD (0x00000001), got 0x%08X", flags)
	}
}

func TestBuildCraftedOBJREF_IID(t *testing.T) {
	oxid := [8]byte{}
	oid := [8]byte{}
	ipid := [16]byte{}

	result := buildCraftedOBJREF(oxid, oid, ipid)

	// Bytes 8-23: IID_IUnknown {00000000-0000-0000-C000-000000000046}
	expectedIID := [16]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	}
	for i := 0; i < 16; i++ {
		if result[8+i] != expectedIID[i] {
			t.Errorf("IID byte %d: expected 0x%02X, got 0x%02X", i, expectedIID[i], result[8+i])
		}
	}
}

func TestBuildCraftedOBJREF_ContainsOXID(t *testing.T) {
	oxid := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	oid := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ipid := [16]byte{}

	result := buildCraftedOBJREF(oxid, oid, ipid)

	// STDOBJREF starts at offset 24 (after sig+flags+IID)
	// stdobjref.flags (4) + cPublicRefs (4) + oxid (8)
	oxidOffset := 24 + 4 + 4
	for i := 0; i < 8; i++ {
		if result[oxidOffset+i] != oxid[i] {
			t.Errorf("OXID byte %d: expected 0x%02X, got 0x%02X", i, oxid[i], result[oxidOffset+i])
		}
	}

	// OID follows OXID
	oidOffset := oxidOffset + 8
	for i := 0; i < 8; i++ {
		if result[oidOffset+i] != oid[i] {
			t.Errorf("OID byte %d: expected 0x%02X, got 0x%02X", i, oid[i], result[oidOffset+i])
		}
	}
}

func TestBuildCraftedOBJREF_Deterministic(t *testing.T) {
	oxid := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	oid := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
	ipid := [16]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	r1 := buildCraftedOBJREF(oxid, oid, ipid)
	r2 := buildCraftedOBJREF(oxid, oid, ipid)

	if len(r1) != len(r2) {
		t.Fatal("same inputs should produce same length output")
	}
	for i := range r1 {
		if r1[i] != r2[i] {
			t.Errorf("byte %d differs: 0x%02X vs 0x%02X", i, r1[i], r2[i])
		}
	}
}
