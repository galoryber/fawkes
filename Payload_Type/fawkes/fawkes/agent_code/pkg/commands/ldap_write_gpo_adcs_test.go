package commands

import (
	"encoding/binary"
	"testing"
)

func TestParseSIDString(t *testing.T) {
	tests := []struct {
		input    string
		wantErr  bool
		wantLen  int
		wantFmt  string
	}{
		{"S-1-5-21-3623811015-3361044348-30300820-1013", false, 28, "S-1-5-21-3623811015-3361044348-30300820-1013"},
		{"S-1-5-18", false, 12, "S-1-5-18"},                                         // SYSTEM
		{"S-1-5-21-0-0-0-500", false, 28, "S-1-5-21-0-0-0-500"},                     // Administrator
		{"invalid", true, 0, ""},
		{"S-0", true, 0, ""},
	}

	for _, tt := range tests {
		sid, err := parseSIDString(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseSIDString(%q) expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSIDString(%q) error: %v", tt.input, err)
			continue
		}
		if len(sid) != tt.wantLen {
			t.Errorf("parseSIDString(%q) len=%d, want %d", tt.input, len(sid), tt.wantLen)
		}

		// Verify round-trip
		formatted := formatSID(sid)
		if formatted != tt.wantFmt {
			t.Errorf("formatSID(parseSIDString(%q)) = %q, want %q", tt.input, formatted, tt.wantFmt)
		}
	}
}

func TestFormatSIDKnownSIDs(t *testing.T) {
	// SYSTEM SID: S-1-5-18
	system := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	if got := formatSID(system); got != "S-1-5-18" {
		t.Errorf("SYSTEM SID = %q, want S-1-5-18", got)
	}

	// Empty/short SID
	if got := formatSID([]byte{1, 2}); got != "0102" {
		t.Errorf("short SID should hex encode, got %q", got)
	}
}

func TestBuildAllowACE(t *testing.T) {
	// Build ACE for SYSTEM SID with GenericAll
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	accessMask := uint32(0x000F01FF)

	ace := buildAllowACE(sid, accessMask)

	// ACE size = 4 (header) + 4 (mask) + 12 (SID) = 20
	expectedSize := 4 + 4 + len(sid)
	if len(ace) != expectedSize {
		t.Errorf("ACE size = %d, want %d", len(ace), expectedSize)
	}

	// Check ACE type = ACCESS_ALLOWED (0)
	if ace[0] != 0x00 {
		t.Errorf("ACE type = %d, want 0 (ACCESS_ALLOWED)", ace[0])
	}

	// Check flags = CONTAINER_INHERIT (0x02)
	if ace[1] != 0x02 {
		t.Errorf("ACE flags = 0x%02x, want 0x02", ace[1])
	}

	// Check ACE size field
	aceSize := binary.LittleEndian.Uint16(ace[2:4])
	if aceSize != uint16(expectedSize) {
		t.Errorf("ACE size field = %d, want %d", aceSize, expectedSize)
	}

	// Check access mask
	mask := binary.LittleEndian.Uint32(ace[4:8])
	if mask != accessMask {
		t.Errorf("access mask = 0x%08x, want 0x%08x", mask, accessMask)
	}

	// Check SID is at offset 8
	for i := range sid {
		if ace[8+i] != sid[i] {
			t.Errorf("SID byte %d: got 0x%02x, want 0x%02x", i, ace[8+i], sid[i])
		}
	}
}

func TestAppendACEToDACL(t *testing.T) {
	// Build a minimal security descriptor with an empty DACL
	// SD header: Revision=1, Sbz1=0, Control=0x8004 (SE_DACL_PRESENT|SE_SELF_RELATIVE),
	//            OffsetOwner=0, OffsetGroup=0, OffsetSacl=0, OffsetDacl=20
	sd := make([]byte, 28) // 20 header + 8 DACL header
	sd[0] = 1              // Revision
	binary.LittleEndian.PutUint16(sd[2:4], 0x8004) // Control
	binary.LittleEndian.PutUint32(sd[16:20], 20)    // OffsetDacl

	// DACL header: Revision=2, Sbz1=0, AclSize=8, AceCount=0, Sbz2=0
	sd[20] = 2                                      // ACL Revision
	binary.LittleEndian.PutUint16(sd[22:24], 8)     // AclSize
	binary.LittleEndian.PutUint16(sd[24:26], 0)     // AceCount

	// Build an ACE
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	ace := buildAllowACE(sid, 0x001F01FF)

	result := appendACEToDACL(sd, ace)
	if result == nil {
		t.Fatal("appendACEToDACL returned nil")
	}

	// New SD should be larger
	if len(result) != len(sd)+len(ace) {
		t.Errorf("new SD size = %d, want %d", len(result), len(sd)+len(ace))
	}

	// DACL should have 1 ACE now
	daclOff := binary.LittleEndian.Uint32(result[16:20])
	newAceCount := binary.LittleEndian.Uint16(result[daclOff+4 : daclOff+6])
	if newAceCount != 1 {
		t.Errorf("ACE count = %d, want 1", newAceCount)
	}

	// ACL size should be increased
	newAclSize := binary.LittleEndian.Uint16(result[daclOff+2 : daclOff+4])
	if int(newAclSize) != 8+len(ace) {
		t.Errorf("new ACL size = %d, want %d", newAclSize, 8+len(ace))
	}
}

func TestAppendACEToDACLInvalidSD(t *testing.T) {
	// Too short
	if appendACEToDACL([]byte{1, 2}, []byte{3}) != nil {
		t.Error("expected nil for short SD")
	}

	// Zero DACL offset
	sd := make([]byte, 20)
	if appendACEToDACL(sd, []byte{1}) != nil {
		t.Error("expected nil for zero DACL offset")
	}
}

func TestSIDRoundTrip(t *testing.T) {
	// Test various SID formats
	sids := []string{
		"S-1-5-21-3623811015-3361044348-30300820-500",
		"S-1-5-21-3623811015-3361044348-30300820-512",
		"S-1-5-18",
		"S-1-5-32-544",
		"S-1-1-0", // Everyone
	}

	for _, sidStr := range sids {
		binary, err := parseSIDString(sidStr)
		if err != nil {
			t.Errorf("parseSIDString(%q) error: %v", sidStr, err)
			continue
		}
		formatted := formatSID(binary)
		if formatted != sidStr {
			t.Errorf("round-trip %q → %q", sidStr, formatted)
		}
	}
}
