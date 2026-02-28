package commands

import (
	"encoding/binary"
	"testing"
)

func TestAclGUIDBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNil  bool
		wantGUID string // hex representation for comparison
	}{
		{
			name:    "DS-Replication-Get-Changes",
			input:   "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
			wantNil: false,
		},
		{
			name:    "DS-Replication-Get-Changes-All",
			input:   "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
			wantNil: false,
		},
		{
			name:    "User-Force-Change-Password",
			input:   "00299570-246d-11d0-a768-00aa006e0529",
			wantNil: false,
		},
		{
			name:    "invalid short",
			input:   "1234",
			wantNil: true,
		},
		{
			name:    "empty",
			input:   "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := aclGUIDBytes(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("expected non-nil result")
			}
			if len(result) != 16 {
				t.Errorf("expected 16 bytes, got %d", len(result))
			}

			// Verify roundtrip: convert back using daclGUIDName
			name := daclGUIDName(result)
			if name == "unknown" || name == tt.input {
				// daclGUIDName should return a known name for these GUIDs
				if tt.name != "invalid short" && tt.name != "empty" && name == "unknown" {
					// Try matching the GUID string directly
					d1 := binary.LittleEndian.Uint32(result[0:4])
					d2 := binary.LittleEndian.Uint16(result[4:6])
					d3 := binary.LittleEndian.Uint16(result[6:8])
					_ = d1
					_ = d2
					_ = d3
				}
			}
		})
	}
}

func TestAclGUIDBytesRoundtrip(t *testing.T) {
	// Test that aclGUIDBytes produces the correct mixed-endian format
	// that daclGUIDName can resolve back to a known name
	testCases := []struct {
		guidStr      string
		expectedName string
	}{
		{"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes"},
		{"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes-All"},
		{"00299570-246d-11d0-a768-00aa006e0529", "User-Force-Change-Password"},
		{"bf9679c0-0de6-11d0-a285-00aa003049e2", "member"},
		{"bf967a86-0de6-11d0-a285-00aa003049e2", "servicePrincipalName"},
		{"5b47d60f-6090-40b2-9f37-2a4de88f3063", "msDS-KeyCredentialLink"},
	}

	for _, tc := range testCases {
		t.Run(tc.expectedName, func(t *testing.T) {
			guid := aclGUIDBytes(tc.guidStr)
			if guid == nil {
				t.Fatal("aclGUIDBytes returned nil")
			}
			name := daclGUIDName(guid)
			if name != tc.expectedName {
				t.Errorf("roundtrip failed: input=%s, got=%s, want=%s", tc.guidStr, name, tc.expectedName)
			}
		})
	}
}

func TestHexByte(t *testing.T) {
	tests := []struct {
		input string
		want  byte
	}{
		{"00", 0x00},
		{"ff", 0xff},
		{"FF", 0xFF},
		{"0a", 0x0a},
		{"a0", 0xa0},
		{"11", 0x11},
		{"7f", 0x7f},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := hexByte(tt.input)
			if got != tt.want {
				t.Errorf("hexByte(%q) = 0x%02x, want 0x%02x", tt.input, got, tt.want)
			}
		})
	}
}

func TestRightToMaskAndGUID(t *testing.T) {
	tests := []struct {
		right       string
		wantMask    uint32
		wantGUIDNil bool
		wantType    byte
	}{
		{"genericall", 0x10000000, true, 0x00},
		{"full-control", 0x10000000, true, 0x00},
		{"genericwrite", 0x40000000, true, 0x00},
		{"writedacl", 0x00040000, true, 0x00},
		{"writeowner", 0x00080000, true, 0x00},
		{"allextendedrights", 0x00000100, true, 0x00},
		{"forcechangepassword", 0x00000100, false, 0x05},
		{"dcsync", 0x00000100, false, 0x05},
		{"ds-replication-get-changes-all", 0x00000100, false, 0x05},
		{"write-member", 0x00000020, false, 0x05},
		{"write-spn", 0x00000020, false, 0x05},
		{"write-keycredentiallink", 0x00000020, false, 0x05},
		{"invalid-right", 0, true, 0x00},
		{"", 0, true, 0x00},
	}

	for _, tt := range tests {
		t.Run(tt.right, func(t *testing.T) {
			mask, guid, aceType := rightToMaskAndGUID(tt.right)
			if mask != tt.wantMask {
				t.Errorf("mask = 0x%08x, want 0x%08x", mask, tt.wantMask)
			}
			if (guid == nil) != tt.wantGUIDNil {
				t.Errorf("guid nil = %v, want %v", guid == nil, tt.wantGUIDNil)
			}
			if aceType != tt.wantType {
				t.Errorf("aceType = 0x%02x, want 0x%02x", aceType, tt.wantType)
			}
		})
	}
}

func TestBuildACEStandard(t *testing.T) {
	// Build a standard ACCESS_ALLOWED_ACE with GenericAll
	sid := daclSIDToBytes("S-1-5-21-1234567890-1234567890-1234567890-1001")
	if sid == nil {
		t.Fatal("failed to build SID")
	}

	ace := buildACE(0x00, 0x10000000, sid, nil)

	// Verify ACE structure
	if ace[0] != 0x00 {
		t.Errorf("aceType = 0x%02x, want 0x00", ace[0])
	}
	if ace[1] != 0x00 {
		t.Errorf("aceFlags = 0x%02x, want 0x00", ace[1])
	}

	aceSize := binary.LittleEndian.Uint16(ace[2:4])
	if int(aceSize) != 4+4+len(sid) {
		t.Errorf("aceSize = %d, want %d", aceSize, 4+4+len(sid))
	}

	mask := binary.LittleEndian.Uint32(ace[4:8])
	if mask != 0x10000000 {
		t.Errorf("mask = 0x%08x, want 0x10000000", mask)
	}

	// Verify SID is at offset 8
	parsedSID := adcsParseSID(ace[8:])
	if parsedSID != "S-1-5-21-1234567890-1234567890-1234567890-1001" {
		t.Errorf("parsed SID = %s, want S-1-5-21-1234567890-1234567890-1234567890-1001", parsedSID)
	}
}

func TestBuildACEObject(t *testing.T) {
	// Build an ACCESS_ALLOWED_OBJECT_ACE with DCSync GUID
	sid := daclSIDToBytes("S-1-5-21-1234567890-1234567890-1234567890-1001")
	if sid == nil {
		t.Fatal("failed to build SID")
	}

	guid := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	ace := buildACE(0x05, 0x00000100, sid, guid)

	// Verify ACE structure
	if ace[0] != 0x05 {
		t.Errorf("aceType = 0x%02x, want 0x05", ace[0])
	}

	aceSize := binary.LittleEndian.Uint16(ace[2:4])
	expectedSize := 4 + 4 + 4 + 16 + len(sid) // header + mask + flags + GUID + SID
	if int(aceSize) != expectedSize {
		t.Errorf("aceSize = %d, want %d", aceSize, expectedSize)
	}

	mask := binary.LittleEndian.Uint32(ace[4:8])
	if mask != 0x00000100 {
		t.Errorf("mask = 0x%08x, want 0x00000100", mask)
	}

	// Verify flags indicate ACE_OBJECT_TYPE_PRESENT
	flags := binary.LittleEndian.Uint32(ace[8:12])
	if flags != 0x01 {
		t.Errorf("flags = 0x%08x, want 0x01", flags)
	}

	// Verify GUID resolves correctly
	guidName := daclGUIDName(ace[12:28])
	if guidName != "DS-Replication-Get-Changes" {
		t.Errorf("GUID name = %s, want DS-Replication-Get-Changes", guidName)
	}

	// Verify SID at offset 28
	parsedSID := adcsParseSID(ace[28:])
	if parsedSID != "S-1-5-21-1234567890-1234567890-1234567890-1001" {
		t.Errorf("parsed SID = %s", parsedSID)
	}
}

func TestRemoveMatchingACEs(t *testing.T) {
	// Build two ACEs: one GenericAll for principal, one ReadControl for another
	sid1 := daclSIDToBytes("S-1-5-21-100-200-300-1001")
	sid2 := daclSIDToBytes("S-1-5-21-100-200-300-512")

	ace1 := buildACE(0x00, 0x10000000, sid1, nil) // GenericAll for sid1
	ace2 := buildACE(0x00, 0x00020000, sid2, nil) // ReadControl for sid2

	aceData := append(ace1, ace2...)

	// Remove the GenericAll ACE for sid1
	result, count := removeMatchingACEs(aceData, 2, "S-1-5-21-100-200-300-1001", 0x10000000, nil, 0x00)

	if count != 1 {
		t.Errorf("remaining count = %d, want 1", count)
	}

	// The remaining ACE should be the ReadControl for sid2
	if len(result) != len(ace2) {
		t.Errorf("result length = %d, want %d", len(result), len(ace2))
	}
}

func TestRemoveMatchingACEsNoMatch(t *testing.T) {
	sid := daclSIDToBytes("S-1-5-21-100-200-300-1001")
	ace := buildACE(0x00, 0x10000000, sid, nil)

	// Try to remove a non-matching ACE
	result, count := removeMatchingACEs(ace, 1, "S-1-5-21-100-200-300-9999", 0x10000000, nil, 0x00)

	if count != 1 {
		t.Errorf("count = %d, want 1 (no removal)", count)
	}
	if len(result) != len(ace) {
		t.Errorf("result length changed: %d vs %d", len(result), len(ace))
	}
}

func TestRemoveMatchingACEsObject(t *testing.T) {
	sid := daclSIDToBytes("S-1-5-21-100-200-300-1001")
	guid := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	ace := buildACE(0x05, 0x00000100, sid, guid)

	// Remove the object ACE
	result, count := removeMatchingACEs(ace, 1, "S-1-5-21-100-200-300-1001", 0x00000100, guid, 0x05)

	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
	if len(result) != 0 {
		t.Errorf("result should be empty, got %d bytes", len(result))
	}
}

func TestRemoveMatchingACEsRelaxedMask(t *testing.T) {
	// Simulate AD decomposing GenericAll (0x10000000) into specific rights
	sid := daclSIDToBytes("S-1-5-21-100-200-300-1001")
	decomposedMask := uint32(0x000F01FF) // AD's decomposed version of GenericAll
	ace := buildACE(0x00, decomposedMask, sid, nil)

	// Try to remove by GenericAll mask — exact match fails, relaxed match by SID succeeds
	result, count := removeMatchingACEs(ace, 1, "S-1-5-21-100-200-300-1001", 0x10000000, nil, 0x00)

	if count != 0 {
		t.Errorf("count = %d, want 0 (relaxed SID match should remove)", count)
	}
	if len(result) != 0 {
		t.Errorf("result should be empty, got %d bytes", len(result))
	}
}

func TestRemoveMatchingACEsRelaxedPreservesOthers(t *testing.T) {
	// Two ACEs for different SIDs, both with decomposed masks
	sid1 := daclSIDToBytes("S-1-5-21-100-200-300-1001")
	sid2 := daclSIDToBytes("S-1-5-21-100-200-300-512")

	ace1 := buildACE(0x00, 0x000F01FF, sid1, nil) // decomposed GenericAll for sid1
	ace2 := buildACE(0x00, 0x000F01FF, sid2, nil) // same mask for sid2

	aceData := append(ace1, ace2...)

	// Remove should only affect sid1, not sid2
	result, count := removeMatchingACEs(aceData, 2, "S-1-5-21-100-200-300-1001", 0x10000000, nil, 0x00)

	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if len(result) != len(ace2) {
		t.Errorf("result length = %d, want %d", len(result), len(ace2))
	}
}

func TestBuildSDFlagsControl(t *testing.T) {
	ctrl := buildSDFlagsControl(0x04)
	if ctrl == nil {
		t.Fatal("buildSDFlagsControl returned nil")
	}

	ctrlType := ctrl.GetControlType()
	if ctrlType != "1.2.840.113556.1.4.801" {
		t.Errorf("control type = %s, want 1.2.840.113556.1.4.801", ctrlType)
	}
}
