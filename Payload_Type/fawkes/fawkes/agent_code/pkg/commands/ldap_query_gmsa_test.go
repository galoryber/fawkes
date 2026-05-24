package commands

import (
	"encoding/binary"
	"testing"
)

// buildTestGMSABlob creates a synthetic MSDS-MANAGEDPASSWORD_BLOB for testing.
// The blob follows the MS-ADTS Section 2.2.17 format.
func buildTestGMSABlob(password []byte) []byte {
	// Fixed header: 16 bytes
	// Password starts at offset 16
	passwordOffset := uint16(16)
	// No previous password
	previousOffset := uint16(0)
	// Query interval at offset 16 + len(password)
	queryIntervalOffset := uint16(16 + len(password))

	totalLen := int(queryIntervalOffset) + 16 // 8 bytes for each interval
	blob := make([]byte, totalLen)

	// Version = 1
	binary.LittleEndian.PutUint16(blob[0:2], 1)
	// Reserved = 0
	binary.LittleEndian.PutUint16(blob[2:4], 0)
	// Length
	binary.LittleEndian.PutUint32(blob[4:8], uint32(totalLen))
	// CurrentPasswordOffset
	binary.LittleEndian.PutUint16(blob[8:10], passwordOffset)
	// PreviousPasswordOffset
	binary.LittleEndian.PutUint16(blob[10:12], previousOffset)
	// QueryPasswordIntervalOffset
	binary.LittleEndian.PutUint16(blob[12:14], queryIntervalOffset)
	// UnchangedPasswordIntervalOffset
	binary.LittleEndian.PutUint16(blob[14:16], queryIntervalOffset+8)

	// Copy password bytes
	copy(blob[16:], password)

	return blob
}

func TestParseManagedPasswordBlob_ValidBlob(t *testing.T) {
	// Test with a known UTF-16LE password "test"
	// "test" in UTF-16LE = 74 00 65 00 73 00 74 00
	utf16Password := []byte{0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00}
	blob := buildTestGMSABlob(utf16Password)

	hash, err := parseManagedPasswordBlob(blob)
	if err != nil {
		t.Fatalf("parseManagedPasswordBlob failed: %v", err)
	}

	if hash == "" {
		t.Error("Expected non-empty NTLM hash")
	}
	if len(hash) != 32 {
		t.Errorf("NTLM hash length = %d, want 32 hex chars", len(hash))
	}

	// NTLM hash of "test" (MD4 of UTF-16LE) is 0CB6948805F797BF2A82807973B89537
	expectedHash := "0CB6948805F797BF2A82807973B89537"
	if hash != expectedHash {
		t.Errorf("NTLM hash = %s, want %s", hash, expectedHash)
	}
}

func TestParseManagedPasswordBlob_EmptyPassword(t *testing.T) {
	// Empty password (just the header)
	blob := buildTestGMSABlob([]byte{})

	// Should fail because password offset == end
	_, err := parseManagedPasswordBlob(blob)
	if err == nil {
		t.Error("Expected error for empty password blob")
	}
}

func TestParseManagedPasswordBlob_TooSmall(t *testing.T) {
	blob := []byte{0x01, 0x00, 0x00, 0x00} // 4 bytes, need 16
	_, err := parseManagedPasswordBlob(blob)
	if err == nil {
		t.Error("Expected error for undersized blob")
	}
}

func TestParseManagedPasswordBlob_WrongVersion(t *testing.T) {
	blob := make([]byte, 32)
	binary.LittleEndian.PutUint16(blob[0:2], 99) // Wrong version
	_, err := parseManagedPasswordBlob(blob)
	if err == nil {
		t.Error("Expected error for wrong version")
	}
}

func TestParseManagedPasswordBlob_BadLength(t *testing.T) {
	blob := make([]byte, 20)
	binary.LittleEndian.PutUint16(blob[0:2], 1)
	binary.LittleEndian.PutUint32(blob[4:8], 9999) // Length exceeds actual
	_, err := parseManagedPasswordBlob(blob)
	if err == nil {
		t.Error("Expected error for length exceeding blob size")
	}
}

func TestParseManagedPasswordBlob_OffsetBeyondBlob(t *testing.T) {
	blob := make([]byte, 20)
	binary.LittleEndian.PutUint16(blob[0:2], 1)
	binary.LittleEndian.PutUint32(blob[4:8], 20)
	binary.LittleEndian.PutUint16(blob[8:10], 100) // Offset beyond blob
	_, err := parseManagedPasswordBlob(blob)
	if err == nil {
		t.Error("Expected error for offset beyond blob")
	}
}

func TestDecodeSID_Valid(t *testing.T) {
	// S-1-5-21-1234-5678-9012-1000
	// Revision=1, SubAuthCount=4, Authority=5
	// SubAuths: 21, 1234, 5678, 9012, 1000 -- wait, that's 5 sub-authorities
	// Actually S-1-5-21-1234-5678-9012-1000 has sub-auths: 21, 1234, 5678, 9012, 1000? No.
	// S-1-5-21-... means revision=1, authority=5, first sub=21, rest follow
	// So 4 sub-auths after the "21": S-1-5-21-1234-5678-9012 has 4 sub-authorities: 21, 1234, 5678, 9012

	data := make([]byte, 8+4*4) // 4 sub-authorities
	data[0] = 1                 // revision
	data[1] = 4                 // subAuthCount
	// Authority = 5 (big-endian in bytes 2-7)
	data[7] = 5
	// Sub-authorities (little-endian)
	binary.LittleEndian.PutUint32(data[8:12], 21)
	binary.LittleEndian.PutUint32(data[12:16], 1234)
	binary.LittleEndian.PutUint32(data[16:20], 5678)
	binary.LittleEndian.PutUint32(data[20:24], 9012)

	sid := decodeSID(data)
	expected := "S-1-5-21-1234-5678-9012"
	if sid != expected {
		t.Errorf("decodeSID = %q, want %q", sid, expected)
	}
}

func TestDecodeSID_TooShort(t *testing.T) {
	sid := decodeSID([]byte{1, 2, 3})
	if sid != "" {
		t.Errorf("Expected empty string for short data, got %q", sid)
	}
}

func TestDecodeSID_ZeroSubAuth(t *testing.T) {
	data := make([]byte, 8)
	data[0] = 1
	data[1] = 0 // 0 sub-authorities — invalid
	sid := decodeSID(data)
	if sid != "" {
		t.Errorf("Expected empty string for 0 sub-auth, got %q", sid)
	}
}

func TestLdapEncodeSID_RoundTrip(t *testing.T) {
	sidStr := "S-1-5-21-3623811015-3361044348-30300820-1013"
	encoded := ldapEncodeSID(sidStr)
	if encoded == "" {
		t.Fatal("ldapEncodeSID returned empty string")
	}
	// Should start with \01 (revision) and contain escaped hex bytes
	if encoded[:3] != "\\01" {
		t.Errorf("Expected to start with \\01, got %s", encoded[:3])
	}
}

func TestLdapEncodeSID_InvalidInput(t *testing.T) {
	result := ldapEncodeSID("not-a-sid")
	if result != "" {
		t.Errorf("Expected empty for invalid SID, got %q", result)
	}
}

func TestExtractSIDsFromBlob_FindsSIDs(t *testing.T) {
	// Build a blob containing a SID
	sid := make([]byte, 8+4*4) // 4 sub-authorities
	sid[0] = 1                 // revision
	sid[1] = 4                 // subAuthCount
	sid[7] = 5                 // authority = 5
	binary.LittleEndian.PutUint32(sid[8:12], 21)
	binary.LittleEndian.PutUint32(sid[12:16], 100)
	binary.LittleEndian.PutUint32(sid[16:20], 200)
	binary.LittleEndian.PutUint32(sid[20:24], 300)

	// Embed the SID in a larger blob
	blob := make([]byte, 50)
	copy(blob[10:], sid) // offset 10

	sids := extractSIDsFromBlob(blob)
	found := false
	for _, s := range sids {
		if s == "S-1-5-21-100-200-300" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected to find S-1-5-21-100-200-300 in %v", sids)
	}
}
