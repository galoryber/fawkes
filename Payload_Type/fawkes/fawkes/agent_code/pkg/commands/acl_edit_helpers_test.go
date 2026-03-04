package commands

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- hexByte Tests ---

func TestHexByte_ValidHex(t *testing.T) {
	tests := []struct {
		input    string
		expected byte
	}{
		{"00", 0x00},
		{"ff", 0xFF},
		{"FF", 0xFF},
		{"0a", 0x0A},
		{"Ab", 0xAB},
		{"42", 0x42},
	}
	for _, tc := range tests {
		got := hexByte(tc.input)
		if got != tc.expected {
			t.Errorf("hexByte(%q) = 0x%02X, want 0x%02X", tc.input, got, tc.expected)
		}
	}
}

// --- aclGUIDBytes Tests ---

func TestAclGUIDBytes_ValidGUID(t *testing.T) {
	// User-Force-Change-Password GUID
	guid := aclGUIDBytes("00299570-246d-11d0-a768-00aa006e0529")
	if guid == nil {
		t.Fatal("aclGUIDBytes returned nil for valid GUID")
	}
	if len(guid) != 16 {
		t.Fatalf("aclGUIDBytes length = %d, want 16", len(guid))
	}
	// Data1 is "00299570" in little-endian → 70 95 29 00
	if guid[0] != 0x70 || guid[1] != 0x95 || guid[2] != 0x29 || guid[3] != 0x00 {
		t.Errorf("Data1 bytes = %02X%02X%02X%02X, want 70952900", guid[0], guid[1], guid[2], guid[3])
	}
}

func TestAclGUIDBytes_InvalidLength(t *testing.T) {
	guid := aclGUIDBytes("short")
	if guid != nil {
		t.Error("aclGUIDBytes should return nil for invalid GUID")
	}
}

func TestAclGUIDBytes_EmptyString(t *testing.T) {
	guid := aclGUIDBytes("")
	if guid != nil {
		t.Error("aclGUIDBytes should return nil for empty string")
	}
}

func TestAclGUIDBytes_DCSyncGUID(t *testing.T) {
	// DS-Replication-Get-Changes
	guid := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	if guid == nil {
		t.Fatal("aclGUIDBytes returned nil for DS-Replication-Get-Changes GUID")
	}
	if len(guid) != 16 {
		t.Fatalf("length = %d, want 16", len(guid))
	}
	// Verify round-trip consistency
	guid2 := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	if !bytes.Equal(guid, guid2) {
		t.Error("aclGUIDBytes not deterministic")
	}
}

// --- rightToMaskAndGUID Tests ---

func TestRightToMaskAndGUID_GenericAll(t *testing.T) {
	mask, guid, aceType := rightToMaskAndGUID("genericall")
	if mask != 0x10000000 {
		t.Errorf("mask = 0x%08X, want 0x10000000", mask)
	}
	if guid != nil {
		t.Error("GenericAll should have nil GUID")
	}
	if aceType != 0x00 {
		t.Errorf("aceType = 0x%02X, want 0x00", aceType)
	}
}

func TestRightToMaskAndGUID_CaseInsensitive(t *testing.T) {
	mask1, _, _ := rightToMaskAndGUID("GenericAll")
	mask2, _, _ := rightToMaskAndGUID("GENERICALL")
	mask3, _, _ := rightToMaskAndGUID("genericall")
	if mask1 != mask2 || mask2 != mask3 {
		t.Error("rightToMaskAndGUID should be case-insensitive")
	}
}

func TestRightToMaskAndGUID_FullControl(t *testing.T) {
	mask, guid, aceType := rightToMaskAndGUID("full-control")
	if mask != 0x10000000 || guid != nil || aceType != 0x00 {
		t.Error("full-control should be alias for genericall")
	}
}

func TestRightToMaskAndGUID_WriteDACL(t *testing.T) {
	mask, guid, aceType := rightToMaskAndGUID("writedacl")
	if mask != 0x00040000 {
		t.Errorf("WriteDACL mask = 0x%08X, want 0x00040000", mask)
	}
	if guid != nil {
		t.Error("WriteDACL should have nil GUID")
	}
	if aceType != 0x00 {
		t.Errorf("aceType = 0x%02X, want 0x00", aceType)
	}
}

func TestRightToMaskAndGUID_DCSync(t *testing.T) {
	mask, guid, aceType := rightToMaskAndGUID("dcsync")
	if mask != 0x00000100 {
		t.Errorf("DCSync mask = 0x%08X, want 0x00000100", mask)
	}
	if guid == nil || len(guid) != 16 {
		t.Fatal("DCSync should have a 16-byte GUID")
	}
	if aceType != 0x05 {
		t.Errorf("aceType = 0x%02X, want 0x05", aceType)
	}
}

func TestRightToMaskAndGUID_DCSyncAlias(t *testing.T) {
	mask1, guid1, type1 := rightToMaskAndGUID("dcsync")
	mask2, guid2, type2 := rightToMaskAndGUID("ds-replication-get-changes")
	if mask1 != mask2 || type1 != type2 {
		t.Error("dcsync and ds-replication-get-changes should have same mask and type")
	}
	if !bytes.Equal(guid1, guid2) {
		t.Error("dcsync and ds-replication-get-changes should have same GUID")
	}
}

func TestRightToMaskAndGUID_ForceChangePassword(t *testing.T) {
	mask, guid, aceType := rightToMaskAndGUID("forcechangepassword")
	if mask != 0x00000100 {
		t.Errorf("mask = 0x%08X, want 0x00000100", mask)
	}
	if guid == nil || len(guid) != 16 {
		t.Fatal("ForceChangePassword should have a 16-byte GUID")
	}
	if aceType != 0x05 {
		t.Errorf("aceType = 0x%02X, want 0x05", aceType)
	}
}

func TestRightToMaskAndGUID_WriteKeyCredentialLink(t *testing.T) {
	mask, guid, aceType := rightToMaskAndGUID("write-keycredentiallink")
	if mask != 0x00000020 {
		t.Errorf("mask = 0x%08X, want 0x00000020", mask)
	}
	if guid == nil {
		t.Fatal("write-keycredentiallink should have a GUID")
	}
	if aceType != 0x05 {
		t.Errorf("aceType = 0x%02X, want 0x05", aceType)
	}
}

func TestRightToMaskAndGUID_Unknown(t *testing.T) {
	mask, guid, aceType := rightToMaskAndGUID("nonexistent")
	if mask != 0 {
		t.Errorf("unknown right mask = 0x%08X, want 0", mask)
	}
	if guid != nil {
		t.Error("unknown right should have nil GUID")
	}
	if aceType != 0x00 {
		t.Errorf("aceType = 0x%02X, want 0x00", aceType)
	}
}

func TestRightToMaskAndGUID_AllRights(t *testing.T) {
	rights := []string{
		"genericall", "full-control", "genericwrite", "writedacl",
		"writeowner", "allextendedrights", "writeproperty",
		"forcechangepassword", "dcsync", "ds-replication-get-changes",
		"ds-replication-get-changes-all", "write-member", "write-spn",
		"write-keycredentiallink",
	}
	for _, r := range rights {
		mask, _, _ := rightToMaskAndGUID(r)
		if mask == 0 {
			t.Errorf("rightToMaskAndGUID(%q) returned mask=0, expected non-zero", r)
		}
	}
}

// --- buildACE Tests ---

// aclTestSID creates a minimal binary SID for S-1-5-21-x-y-z-RID
func aclTestSID(rid uint32) []byte {
	// S-1-5-21-100-200-300-<rid>
	sid := make([]byte, 28)
	sid[0] = 1  // Revision
	sid[1] = 4  // SubAuthorityCount
	sid[7] = 5  // IdentifierAuthority = 5 (NT Authority)
	binary.LittleEndian.PutUint32(sid[8:12], 21)
	binary.LittleEndian.PutUint32(sid[12:16], 100)
	binary.LittleEndian.PutUint32(sid[16:20], 200)
	binary.LittleEndian.PutUint32(sid[20:24], 300)
	binary.LittleEndian.PutUint32(sid[24:28], rid)
	return sid
}

func TestBuildACE_StandardType(t *testing.T) {
	sid := aclTestSID(1001)
	ace := buildACE(0x00, 0x10000000, sid, nil)

	if ace[0] != 0x00 {
		t.Errorf("AceType = 0x%02X, want 0x00", ace[0])
	}

	expectedSize := 4 + 4 + len(sid)
	gotSize := int(binary.LittleEndian.Uint16(ace[2:4]))
	if gotSize != expectedSize {
		t.Errorf("AceSize = %d, want %d", gotSize, expectedSize)
	}

	gotMask := binary.LittleEndian.Uint32(ace[4:8])
	if gotMask != 0x10000000 {
		t.Errorf("AccessMask = 0x%08X, want 0x10000000", gotMask)
	}

	if !bytes.Equal(ace[8:], sid) {
		t.Error("SID not correctly copied into ACE")
	}
}

func TestBuildACE_ObjectType(t *testing.T) {
	sid := aclTestSID(1001)
	guid := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")

	ace := buildACE(0x05, 0x00000100, sid, guid)

	if ace[0] != 0x05 {
		t.Errorf("AceType = 0x%02X, want 0x05", ace[0])
	}

	expectedSize := 4 + 4 + 4 + 16 + len(sid)
	gotSize := int(binary.LittleEndian.Uint16(ace[2:4]))
	if gotSize != expectedSize {
		t.Errorf("AceSize = %d, want %d", gotSize, expectedSize)
	}

	gotMask := binary.LittleEndian.Uint32(ace[4:8])
	if gotMask != 0x00000100 {
		t.Errorf("AccessMask = 0x%08X, want 0x00000100", gotMask)
	}

	gotFlags := binary.LittleEndian.Uint32(ace[8:12])
	if gotFlags != 0x01 {
		t.Errorf("Flags = 0x%08X, want 0x01 (ACE_OBJECT_TYPE_PRESENT)", gotFlags)
	}

	if !bytes.Equal(ace[12:28], guid) {
		t.Error("GUID not correctly copied into ACE")
	}

	if !bytes.Equal(ace[28:], sid) {
		t.Error("SID not correctly copied into object ACE")
	}
}

func TestBuildACE_ObjectTypeNilGUID(t *testing.T) {
	sid := aclTestSID(1001)
	// When aceType is 0x05 but GUID is nil, should fall through to standard type
	ace := buildACE(0x05, 0x10000000, sid, nil)

	if ace[0] != 0x00 {
		t.Errorf("AceType = 0x%02X, want 0x00 (fallback to standard)", ace[0])
	}
}

func TestBuildACE_ObjectTypeShortGUID(t *testing.T) {
	sid := aclTestSID(1001)
	// GUID too short — should fall through to standard type
	ace := buildACE(0x05, 0x10000000, sid, []byte{0x01, 0x02})

	if ace[0] != 0x00 {
		t.Errorf("AceType = 0x%02X, want 0x00 (fallback for short GUID)", ace[0])
	}
}

// --- removeMatchingACEs Tests ---

func TestRemoveMatchingACEs_ExactMatch(t *testing.T) {
	sid := aclTestSID(1001)
	sidStr := adcsParseSID(sid)

	// Build 2 standard ACEs: one matching, one not
	ace1 := buildACE(0x00, 0x10000000, sid, nil)
	ace2 := buildACE(0x00, 0x00040000, aclTestSID(1002), nil)

	aceData := append(ace1, ace2...)

	result, remaining := removeMatchingACEs(aceData, 2, sidStr, 0x10000000, nil, 0x00)
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1", remaining)
	}
	if len(result) != len(ace2) {
		t.Errorf("result length = %d, want %d", len(result), len(ace2))
	}
}

func TestRemoveMatchingACEs_NoMatch(t *testing.T) {
	sid := aclTestSID(1001)
	ace := buildACE(0x00, 0x10000000, sid, nil)

	// Try to remove by different SID
	result, remaining := removeMatchingACEs(ace, 1, "S-1-5-21-999-999-999-9999", 0x10000000, nil, 0x00)
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1 (no match should keep all)", remaining)
	}
	if !bytes.Equal(result, ace) {
		t.Error("result should equal original when no match found")
	}
}

func TestRemoveMatchingACEs_RelaxedMatch(t *testing.T) {
	sid := aclTestSID(1001)
	sidStr := adcsParseSID(sid)

	// Build an ACE with a different mask (simulating AD decomposing GenericAll)
	ace := buildACE(0x00, 0x000F01FF, sid, nil) // Full control decomposed

	// Try to remove with GenericAll mask — exact won't match, relaxed should
	result, remaining := removeMatchingACEs([]byte(ace), 1, sidStr, 0x10000000, nil, 0x00)
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0 (relaxed match should remove)", remaining)
	}
	if len(result) != 0 {
		t.Errorf("result length = %d, want 0", len(result))
	}
}

func TestRemoveMatchingACEs_ObjectACE(t *testing.T) {
	sid := aclTestSID(1001)
	sidStr := adcsParseSID(sid)
	guid := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")

	ace := buildACE(0x05, 0x00000100, sid, guid)

	result, remaining := removeMatchingACEs(ace, 1, sidStr, 0x00000100, guid, 0x05)
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0", remaining)
	}
	if len(result) != 0 {
		t.Errorf("result length = %d, want 0", len(result))
	}
}

func TestRemoveMatchingACEs_ObjectACE_WrongGUID(t *testing.T) {
	sid := aclTestSID(1001)
	sidStr := adcsParseSID(sid)
	guid1 := aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	guid2 := aclGUIDBytes("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") // Different GUID

	ace := buildACE(0x05, 0x00000100, sid, guid1)

	_, remaining := removeMatchingACEs(ace, 1, sidStr, 0x00000100, guid2, 0x05)
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1 (wrong GUID should not match)", remaining)
	}
}

func TestRemoveMatchingACEs_EmptyData(t *testing.T) {
	result, remaining := removeMatchingACEs(nil, 0, "S-1-5-21-1-2-3-4", 0x10000000, nil, 0x00)
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0", remaining)
	}
	if len(result) != 0 {
		t.Errorf("result length = %d, want 0", len(result))
	}
}

func TestRemoveMatchingACEs_MultipleMatches(t *testing.T) {
	sid := aclTestSID(1001)
	sidStr := adcsParseSID(sid)

	// Build 3 ACEs: 2 matching, 1 different
	ace1 := buildACE(0x00, 0x10000000, sid, nil)
	ace2 := buildACE(0x00, 0x00040000, aclTestSID(1002), nil)
	ace3 := buildACE(0x00, 0x10000000, sid, nil) // Duplicate

	aceData := append(ace1, ace2...)
	aceData = append(aceData, ace3...)

	result, remaining := removeMatchingACEs(aceData, 3, sidStr, 0x10000000, nil, 0x00)
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1", remaining)
	}
	if len(result) != len(ace2) {
		t.Errorf("result length = %d, want %d", len(result), len(ace2))
	}
}

func TestRemoveMatchingACEs_TypeMismatch(t *testing.T) {
	sid := aclTestSID(1001)
	sidStr := adcsParseSID(sid)

	// Standard ACE, but try to remove with object type
	ace := buildACE(0x00, 0x10000000, sid, nil)

	_, remaining := removeMatchingACEs(ace, 1, sidStr, 0x10000000,
		aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"), 0x05)
	if remaining != 1 {
		t.Errorf("remaining = %d, want 1 (type mismatch should not remove)", remaining)
	}
}
