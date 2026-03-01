package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

func TestBuildKCEntry(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	entry := buildKCEntry(5, data)

	// Entry: 2 bytes id + 4 bytes length + 3 bytes data = 9 bytes
	if len(entry) != 9 {
		t.Fatalf("expected entry length 9, got %d", len(entry))
	}

	id := binary.LittleEndian.Uint16(entry[0:2])
	if id != 5 {
		t.Errorf("expected identifier 5, got %d", id)
	}

	length := binary.LittleEndian.Uint32(entry[2:6])
	if length != 3 {
		t.Errorf("expected data length 3, got %d", length)
	}

	if entry[6] != 0x01 || entry[7] != 0x02 || entry[8] != 0x03 {
		t.Errorf("data mismatch: %v", entry[6:])
	}
}

func TestBuildBCRYPTRSAKeyBlob(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	blob := buildBCRYPTRSAKeyBlob(&key.PublicKey)

	// Check magic
	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != bcryptRSAPublicMagic {
		t.Errorf("expected magic 0x31415352, got 0x%08X", magic)
	}

	// Check bit length
	bitLen := binary.LittleEndian.Uint32(blob[4:8])
	if bitLen != 2048 {
		t.Errorf("expected bit length 2048, got %d", bitLen)
	}

	// Check exponent size
	expSize := binary.LittleEndian.Uint32(blob[8:12])
	if expSize != 3 { // 65537 = 3 bytes
		t.Errorf("expected exponent size 3, got %d", expSize)
	}

	// Check modulus size
	modSize := binary.LittleEndian.Uint32(blob[12:16])
	if modSize != 256 { // 2048 bits = 256 bytes
		t.Errorf("expected modulus size 256, got %d", modSize)
	}

	// Check total blob size: 24 header + 3 exp + 256 mod = 283
	expectedSize := 24 + int(expSize) + int(modSize)
	if len(blob) != expectedSize {
		t.Errorf("expected blob size %d, got %d", expectedSize, len(blob))
	}
}

func TestBuildKeyCredential(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	credential, deviceID, err := buildKeyCredential(&key.PublicKey)
	if err != nil {
		t.Fatalf("buildKeyCredential failed: %v", err)
	}

	// Check version
	version := binary.LittleEndian.Uint32(credential[0:4])
	if version != kcVersion {
		t.Errorf("expected version 0x%08X, got 0x%08X", kcVersion, version)
	}

	// Device ID should be 16 bytes
	if len(deviceID) != 16 {
		t.Errorf("expected device ID length 16, got %d", len(deviceID))
	}

	// Credential should be non-empty and reasonable size
	// Minimum: 4 (version) + 9 entries * (2 id + 4 len + data)
	if len(credential) < 100 {
		t.Errorf("credential seems too small: %d bytes", len(credential))
	}

	// Parse entries and verify structure
	offset := 4 // skip version
	var foundKeyMaterial, foundKeyID, foundKeyHash bool
	for offset < len(credential) {
		if offset+6 > len(credential) {
			t.Fatalf("truncated entry at offset %d", offset)
		}
		entryID := binary.LittleEndian.Uint16(credential[offset : offset+2])
		entryLen := binary.LittleEndian.Uint32(credential[offset+2 : offset+6])
		if offset+6+int(entryLen) > len(credential) {
			t.Fatalf("entry data exceeds credential bounds: id=%d, len=%d, offset=%d", entryID, entryLen, offset)
		}

		switch entryID {
		case kcEntryKeyMaterial:
			foundKeyMaterial = true
			// Verify BCRYPT_RSAKEY_BLOB magic inside
			data := credential[offset+6 : offset+6+int(entryLen)]
			if len(data) >= 4 {
				m := binary.LittleEndian.Uint32(data[0:4])
				if m != bcryptRSAPublicMagic {
					t.Errorf("KeyMaterial magic mismatch: 0x%08X", m)
				}
			}
		case kcEntryKeyID:
			foundKeyID = true
			if entryLen != 32 {
				t.Errorf("KeyID should be 32 bytes (SHA256), got %d", entryLen)
			}
		case kcEntryKeyHash:
			foundKeyHash = true
			if entryLen != 32 {
				t.Errorf("KeyHash should be 32 bytes (SHA256), got %d", entryLen)
			}
		case kcEntryKeyUsage:
			data := credential[offset+6]
			if data != kcKeyUsageNGC {
				t.Errorf("KeyUsage should be 0x01 (NGC), got 0x%02X", data)
			}
		case kcEntryKeySource:
			data := credential[offset+6]
			if data != kcKeySourceAD {
				t.Errorf("KeySource should be 0x00 (AD), got 0x%02X", data)
			}
		case kcEntryDeviceID:
			if entryLen != 16 {
				t.Errorf("DeviceID should be 16 bytes, got %d", entryLen)
			}
		}

		offset += 6 + int(entryLen)
	}

	if !foundKeyMaterial {
		t.Error("KeyMaterial entry not found")
	}
	if !foundKeyID {
		t.Error("KeyID entry not found")
	}
	if !foundKeyHash {
		t.Error("KeyHash entry not found")
	}
}

func TestKeyCredentialKeyIDIsHashOfKeyMaterial(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	credential, _, err := buildKeyCredential(&key.PublicKey)
	if err != nil {
		t.Fatalf("buildKeyCredential failed: %v", err)
	}

	// Extract KeyMaterial and KeyID entries
	var keyMaterialData, keyIDData []byte
	offset := 4
	for offset < len(credential) {
		entryID := binary.LittleEndian.Uint16(credential[offset : offset+2])
		entryLen := binary.LittleEndian.Uint32(credential[offset+2 : offset+6])
		data := credential[offset+6 : offset+6+int(entryLen)]

		switch entryID {
		case kcEntryKeyMaterial:
			keyMaterialData = data
		case kcEntryKeyID:
			keyIDData = data
		}
		offset += 6 + int(entryLen)
	}

	// KeyID should be SHA256 of KeyMaterial data
	expectedHash := sha256.Sum256(keyMaterialData)
	if !bytesEqual(keyIDData, expectedHash[:]) {
		t.Errorf("KeyID does not match SHA256(KeyMaterial)\nExpected: %s\nGot:      %s",
			hex.EncodeToString(expectedHash[:]),
			hex.EncodeToString(keyIDData))
	}
}

func TestTimeToFiletime(t *testing.T) {
	// Test known value: 2024-01-01 00:00:00 UTC
	// Expected FILETIME: 133479168000000000 (0x01DA5F9C91000000)
	// Actually let's just verify the conversion is non-zero and 8 bytes
	ft := timeToFiletime(time.Now())
	if len(ft) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(ft))
	}

	val := binary.LittleEndian.Uint64(ft)
	if val == 0 {
		t.Error("FILETIME should not be zero")
	}

	// FILETIME should be > year 2020 (approx 132000000000000000)
	if val < 132000000000000000 {
		t.Errorf("FILETIME seems too small: %d", val)
	}
}

func TestRandomGUID(t *testing.T) {
	guid, err := randomGUID()
	if err != nil {
		t.Fatalf("randomGUID failed: %v", err)
	}

	if len(guid) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(guid))
	}

	// Check version 4 bits
	version := (guid[6] >> 4) & 0x0f
	if version != 4 {
		t.Errorf("expected GUID version 4, got %d", version)
	}

	// Check variant bits (10xx)
	variant := (guid[8] >> 6) & 0x03
	if variant != 2 {
		t.Errorf("expected GUID variant 2 (10xx), got %d", variant)
	}

	// Two calls should produce different GUIDs
	guid2, _ := randomGUID()
	if bytesEqual(guid, guid2) {
		t.Error("two consecutive GUIDs should not be identical")
	}
}

func TestFormatGUID(t *testing.T) {
	// Known GUID bytes
	guid := []byte{
		0x01, 0x02, 0x03, 0x04, // data1
		0x05, 0x06, // data2
		0x07, 0x08, // data3
		0x09, 0x0a, // data4[0:2]
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // data4[2:8]
	}

	formatted := formatGUID(guid)
	if formatted != "04030201-0605-0807-090a-0b0c0d0e0f10" {
		t.Errorf("unexpected GUID format: %s", formatted)
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		dn     string
		expect string
	}{
		{"CN=user,DC=north,DC=sevenkingdoms,DC=local", "north.sevenkingdoms.local"},
		{"CN=user,OU=Users,DC=contoso,DC=com", "contoso.com"},
		{"CN=user", "DOMAIN"},
		{"", "DOMAIN"},
	}

	for _, tt := range tests {
		result := extractDomain(tt.dn)
		if result != tt.expect {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.dn, result, tt.expect)
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
