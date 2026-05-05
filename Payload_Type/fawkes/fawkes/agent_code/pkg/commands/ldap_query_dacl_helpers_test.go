package commands

import (
	"strings"
	"testing"
)

// --- daclSIDToBytes tests ---

func TestDaclSIDToBytes_DomainSID(t *testing.T) {
	// S-1-5-21-domain-rid
	b := daclSIDToBytes("S-1-5-21-111-222-333-500")
	if b == nil {
		t.Fatal("expected non-nil bytes for valid SID")
	}
	// Revision=1, SubAuthCount=5 (21, 111, 222, 333, 500)
	if b[0] != 1 {
		t.Errorf("revision = %d, want 1", b[0])
	}
	if b[1] != 5 {
		t.Errorf("subAuthCount = %d, want 5", b[1])
	}
	// Total length: 8 + 5*4 = 28
	if len(b) != 28 {
		t.Errorf("length = %d, want 28", len(b))
	}
}

func TestDaclSIDToBytes_BuiltinSID(t *testing.T) {
	// S-1-5-32-544 (BUILTIN\Administrators)
	b := daclSIDToBytes("S-1-5-32-544")
	if b == nil {
		t.Fatal("expected non-nil bytes")
	}
	// Revision=1, SubAuthCount=2 (32, 544)
	if b[0] != 1 {
		t.Errorf("revision = %d, want 1", b[0])
	}
	if b[1] != 2 {
		t.Errorf("subAuthCount = %d, want 2", b[1])
	}
}

func TestDaclSIDToBytes_InvalidPrefix(t *testing.T) {
	b := daclSIDToBytes("X-1-5-32-544")
	if b != nil {
		t.Error("invalid prefix should return nil")
	}
}

func TestDaclSIDToBytes_TooShort(t *testing.T) {
	b := daclSIDToBytes("S-1-5")
	if b != nil {
		t.Error("too-short SID should return nil")
	}
}

func TestDaclSIDToBytes_AuthorityEncoding(t *testing.T) {
	// S-1-5-... authority=5 should be big-endian in bytes[2:8]
	b := daclSIDToBytes("S-1-5-32-544")
	if b == nil {
		t.Fatal("unexpected nil")
	}
	// Authority=5: bytes 2-7 should be [0,0,0,0,0,5]
	for i := 2; i < 7; i++ {
		if b[i] != 0 {
			t.Errorf("authority byte %d = %d, want 0", i-2, b[i])
		}
	}
	if b[7] != 5 {
		t.Errorf("authority last byte = %d, want 5", b[7])
	}
}

// --- daclWellKnownRID tests ---

func TestDaclWellKnownRID_DomainAdmins(t *testing.T) {
	got := daclWellKnownRID("S-1-5-21-111-222-333-512")
	if got != "Domain Admins" {
		t.Errorf("RID 512 = %q, want Domain Admins", got)
	}
}

func TestDaclWellKnownRID_EnterpriseAdmins(t *testing.T) {
	got := daclWellKnownRID("S-1-5-21-111-222-333-519")
	if got != "Enterprise Admins" {
		t.Errorf("RID 519 = %q, want Enterprise Admins", got)
	}
}

func TestDaclWellKnownRID_KnownRIDs(t *testing.T) {
	cases := []struct {
		rid  string
		want string
	}{
		{"S-1-5-21-1-2-3-500", "Administrator"},
		{"S-1-5-21-1-2-3-502", "krbtgt"},
		{"S-1-5-21-1-2-3-513", "Domain Users"},
		{"S-1-5-21-1-2-3-516", "Domain Controllers"},
		{"S-1-5-21-1-2-3-518", "Schema Admins"},
		{"S-1-5-21-1-2-3-526", "Key Admins"},
	}
	for _, tc := range cases {
		got := daclWellKnownRID(tc.rid)
		if got != tc.want {
			t.Errorf("daclWellKnownRID(%q) = %q, want %q", tc.rid, got, tc.want)
		}
	}
}

func TestDaclWellKnownRID_Unknown(t *testing.T) {
	got := daclWellKnownRID("S-1-5-21-1-2-3-9999")
	if got != "" {
		t.Errorf("unknown RID = %q, want empty string", got)
	}
}

func TestDaclWellKnownRID_TooShort(t *testing.T) {
	got := daclWellKnownRID("S-1-5")
	if got != "" {
		t.Errorf("short SID = %q, want empty", got)
	}
}

// --- daclDescribePermissions tests ---

func TestDaclDescribePermissions_GenericAll(t *testing.T) {
	got := daclDescribePermissions(0x10000000, 0, nil)
	if !strings.Contains(got, "GenericAll") {
		t.Errorf("GenericAll = %q, want GenericAll in output", got)
	}
	if !strings.Contains(got, "FULL CONTROL") {
		t.Errorf("GenericAll = %q, want FULL CONTROL", got)
	}
}

func TestDaclDescribePermissions_WriteOwner(t *testing.T) {
	got := daclDescribePermissions(0x00080000, 0, nil)
	if !strings.Contains(got, "WriteOwner") {
		t.Errorf("WriteOwner = %q, want WriteOwner", got)
	}
}

func TestDaclDescribePermissions_WriteDACL(t *testing.T) {
	got := daclDescribePermissions(0x00040000, 0, nil)
	if !strings.Contains(got, "WriteDACL") {
		t.Errorf("WriteDACL = %q, want WriteDACL", got)
	}
}

func TestDaclDescribePermissions_AllExtendedRights(t *testing.T) {
	// Bit 0x100 without object-type ACE (aceType=0)
	got := daclDescribePermissions(0x00000100, 0, nil)
	if !strings.Contains(got, "AllExtendedRights") {
		t.Errorf("AllExtendedRights = %q, want AllExtendedRights", got)
	}
}

func TestDaclDescribePermissions_ExtendedRightWithGUID(t *testing.T) {
	// DS-Replication-Get-Changes GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (mixed-endian)
	// Bytes (LE for first 3 groups): aa f6 31 11 | 07 9c | d1 11 | f7 9f | 00 c0 4f c2 dc d2
	guid := []byte{0xaa, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	got := daclDescribePermissions(0x00000100, 0x05, guid)
	if !strings.Contains(got, "ExtendedRight") {
		t.Errorf("ExtendedRight with GUID = %q, want ExtendedRight", got)
	}
	if !strings.Contains(got, "DS-Replication-Get-Changes") {
		t.Errorf("ExtendedRight with GUID = %q, want DS-Replication-Get-Changes", got)
	}
}

func TestDaclDescribePermissions_ZeroMask(t *testing.T) {
	got := daclDescribePermissions(0, 0, nil)
	// Should return hex representation
	if !strings.Contains(got, "0x") {
		t.Errorf("zero mask = %q, want hex representation", got)
	}
}

func TestDaclDescribePermissions_CreateDeleteChild(t *testing.T) {
	got := daclDescribePermissions(0x00000006, 0, nil) // CreateChild|DeleteChild
	if !strings.Contains(got, "CreateChild") {
		t.Errorf("CreateChild = %q, want CreateChild", got)
	}
	if !strings.Contains(got, "DeleteChild") {
		t.Errorf("DeleteChild = %q, want DeleteChild", got)
	}
}

// --- daclAssessRisk tests ---

func TestDaclAssessRisk_SystemIsStandard(t *testing.T) {
	// SYSTEM with GenericAll should be standard (expected)
	got := daclAssessRisk(0x10000000, 0, "S-1-5-18", nil)
	if got != "standard" {
		t.Errorf("SYSTEM GenericAll = %q, want standard", got)
	}
}

func TestDaclAssessRisk_EveryoneWithWriteIsDangerous(t *testing.T) {
	// Everyone (S-1-1-0) with WriteDACL
	got := daclAssessRisk(0x00040000, 0, "S-1-1-0", nil)
	if got != "dangerous" {
		t.Errorf("Everyone WriteDACL = %q, want dangerous", got)
	}
}

func TestDaclAssessRisk_UnknownSIDWithWriteIsNotable(t *testing.T) {
	// Unknown non-admin SID with GenericWrite
	got := daclAssessRisk(0x40000000, 0, "S-1-5-21-1-2-3-1001", nil)
	if got != "notable" {
		t.Errorf("unknown SID GenericWrite = %q, want notable", got)
	}
}

func TestDaclAssessRisk_StandardReadIsStandard(t *testing.T) {
	// Read-only permission is always standard
	got := daclAssessRisk(0x00020000, 0, "S-1-1-0", nil) // ReadControl only
	if got != "standard" {
		t.Errorf("Everyone ReadControl = %q, want standard", got)
	}
}

func TestDaclAssessRisk_ChangePasswordNotDangerous(t *testing.T) {
	// User-Change-Password extended right (ab721a53) should not be dangerous
	// GUID bytes (LE): 53 1a 72 ab | 2f 1e | d0 11 | 98 19 | 00 aa 00 40 52 9b
	guid := []byte{0x53, 0x1a, 0x72, 0xab, 0x2f, 0x1e, 0xd0, 0x11, 0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b}
	got := daclAssessRisk(0x00000100, 0x05, "S-1-1-0", guid)
	// Change-Password is not treated as dangerous
	if got == "dangerous" {
		t.Error("User-Change-Password should not be classified as dangerous")
	}
}

func TestDaclAssessRisk_DomainAdminsWithWriteIsStandard(t *testing.T) {
	// Domain Admins (RID 512) with dangerous perms = standard (expected)
	got := daclAssessRisk(0x10000000, 0, "S-1-5-21-1-2-3-512", nil)
	if got != "standard" {
		t.Errorf("Domain Admins GenericAll = %q, want standard", got)
	}
}

// --- daclGUIDName tests ---

func TestDaclGUIDName_ForceChangePassword(t *testing.T) {
	// 00299570-246d-11d0-a768-00aa006e0529
	// LE bytes: 70 95 29 00 | 6d 24 | d0 11 | a7 68 | 00 aa 00 6e 05 29
	guid := []byte{0x70, 0x95, 0x29, 0x00, 0x6d, 0x24, 0xd0, 0x11, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29}
	got := daclGUIDName(guid)
	if got != "User-Force-Change-Password" {
		t.Errorf("daclGUIDName = %q, want User-Force-Change-Password", got)
	}
}

func TestDaclGUIDName_DCSync1(t *testing.T) {
	// DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
	guid := []byte{0xaa, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	got := daclGUIDName(guid)
	if got != "DS-Replication-Get-Changes" {
		t.Errorf("daclGUIDName = %q, want DS-Replication-Get-Changes", got)
	}
}

func TestDaclGUIDName_KeyCredentialLink(t *testing.T) {
	// msDS-KeyCredentialLink: 5b47d60f-6090-40b2-9f37-2a4de88f3063
	guid := []byte{0x0f, 0xd6, 0x47, 0x5b, 0x90, 0x60, 0xb2, 0x40, 0x9f, 0x37, 0x2a, 0x4d, 0xe8, 0x8f, 0x30, 0x63}
	got := daclGUIDName(guid)
	if got != "msDS-KeyCredentialLink" {
		t.Errorf("daclGUIDName = %q, want msDS-KeyCredentialLink", got)
	}
}

func TestDaclGUIDName_UnknownGUID(t *testing.T) {
	// All zeros — not in the known map
	guid := make([]byte, 16)
	got := daclGUIDName(guid)
	// Should return the GUID string, not "unknown"
	if got == "" {
		t.Error("unknown GUID should return GUID string, not empty")
	}
}

func TestDaclGUIDName_WrongLength(t *testing.T) {
	got := daclGUIDName([]byte{1, 2, 3})
	if got != "unknown" {
		t.Errorf("wrong-length guid = %q, want unknown", got)
	}
}

func TestDaclGUIDName_Nil(t *testing.T) {
	got := daclGUIDName(nil)
	if got != "unknown" {
		t.Errorf("nil guid = %q, want unknown", got)
	}
}
