package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// --- expandDESKey tests ---

func TestExpandDESKey_Length(t *testing.T) {
	input := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD}
	result := expandDESKey(input)
	if len(result) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(result))
	}
}

func TestExpandDESKey_ParityBits(t *testing.T) {
	// After expansion, each byte is shifted left by 1 and masked with 0xFE,
	// so the LSB should always be 0.
	input := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	result := expandDESKey(input)
	for i, b := range result {
		if b&0x01 != 0 {
			t.Errorf("byte %d (0x%02x) should have LSB=0 (parity)", i, b)
		}
	}
}

func TestExpandDESKey_ZeroInput(t *testing.T) {
	input := make([]byte, 7)
	result := expandDESKey(input)
	for i, b := range result {
		if b != 0 {
			t.Errorf("byte %d should be 0 for zero input, got 0x%02x", i, b)
		}
	}
}

func TestExpandDESKey_Deterministic(t *testing.T) {
	input := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE}
	r1 := expandDESKey(input)
	r2 := expandDESKey(input)
	for i := range r1 {
		if r1[i] != r2[i] {
			t.Errorf("byte %d differs: 0x%02x vs 0x%02x", i, r1[i], r2[i])
		}
	}
}

// --- desKeysFromRID tests ---

func TestDesKeysFromRID_Administrator(t *testing.T) {
	key1, key2 := desKeysFromRID(500)
	if len(key1) != 8 || len(key2) != 8 {
		t.Fatalf("expected 8-byte keys, got %d and %d", len(key1), len(key2))
	}
	// Keys should be different for different halves of the RID
	same := true
	for i := 0; i < 8; i++ {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("key1 and key2 should be different for RID 500")
	}
}

func TestDesKeysFromRID_Deterministic(t *testing.T) {
	k1a, k2a := desKeysFromRID(1001)
	k1b, k2b := desKeysFromRID(1001)
	for i := 0; i < 8; i++ {
		if k1a[i] != k1b[i] {
			t.Errorf("key1 byte %d not deterministic", i)
		}
		if k2a[i] != k2b[i] {
			t.Errorf("key2 byte %d not deterministic", i)
		}
	}
}

func TestDesKeysFromRID_DifferentRIDs(t *testing.T) {
	k1a, _ := desKeysFromRID(500)
	k1b, _ := desKeysFromRID(501)
	same := true
	for i := 0; i < 8; i++ {
		if k1a[i] != k1b[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different RIDs should produce different keys")
	}
}

func TestDesKeysFromRID_ZeroRID(t *testing.T) {
	key1, key2 := desKeysFromRID(0)
	if len(key1) != 8 || len(key2) != 8 {
		t.Fatalf("expected 8-byte keys for RID 0")
	}
}

// --- utf16LEToString tests ---

func TestUtf16LEToString_ASCII(t *testing.T) {
	// "Admin" in UTF-16LE
	input := []byte{0x41, 0x00, 0x64, 0x00, 0x6D, 0x00, 0x69, 0x00, 0x6E, 0x00}
	result := utf16LEToString(input)
	if result != "Admin" {
		t.Errorf("expected %q, got %q", "Admin", result)
	}
}

func TestUtf16LEToString_Empty(t *testing.T) {
	result := utf16LEToString([]byte{})
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestUtf16LEToString_OddLength(t *testing.T) {
	// "A" + trailing byte (odd length, should truncate)
	input := []byte{0x41, 0x00, 0x42}
	result := utf16LEToString(input)
	if result != "A" {
		t.Errorf("expected %q, got %q", "A", result)
	}
}

func TestUtf16LEToString_Unicode(t *testing.T) {
	// Euro sign (€ = U+20AC) in UTF-16LE
	input := []byte{0xAC, 0x20}
	result := utf16LEToString(input)
	if result != "€" {
		t.Errorf("expected %q, got %q", "€", result)
	}
}

// --- parseHexUint32 tests ---

func TestParseHexUint32_Valid(t *testing.T) {
	tests := []struct {
		input  string
		expect uint32
	}{
		{"000001F4", 500},
		{"000003E9", 1001},
		{"000001F5", 501},
		{"FFFFFFFF", 4294967295},
		{"0", 0},
		{"1f4", 500},
	}
	for _, tt := range tests {
		result, err := parseHexUint32(tt.input)
		if err != nil {
			t.Errorf("parseHexUint32(%q) failed: %v", tt.input, err)
			continue
		}
		if result != tt.expect {
			t.Errorf("parseHexUint32(%q) = %d, want %d", tt.input, result, tt.expect)
		}
	}
}

func TestParseHexUint32_Invalid(t *testing.T) {
	_, err := parseHexUint32("notahex")
	if err == nil {
		t.Error("parseHexUint32(\"notahex\") should fail")
	}
}

// --- bootKeyPerm tests ---

func TestBootKeyPermutation_Unique(t *testing.T) {
	seen := make(map[int]bool)
	for _, v := range bootKeyPerm {
		if v < 0 || v > 15 {
			t.Errorf("permutation value %d out of range", v)
		}
		if seen[v] {
			t.Errorf("duplicate permutation value %d", v)
		}
		seen[v] = true
	}
	if len(seen) != 16 {
		t.Errorf("expected 16 unique values, got %d", len(seen))
	}
}

// --- emptyHash constants tests ---

func TestEmptyHashConstants(t *testing.T) {
	_, err := hex.DecodeString(emptyLMHash)
	if err != nil {
		t.Errorf("emptyLMHash is not valid hex: %v", err)
	}
	_, err = hex.DecodeString(emptyNTHash)
	if err != nil {
		t.Errorf("emptyNTHash is not valid hex: %v", err)
	}
	if len(emptyLMHash) != 32 {
		t.Errorf("emptyLMHash length: %d, want 32", len(emptyLMHash))
	}
	if len(emptyNTHash) != 32 {
		t.Errorf("emptyNTHash length: %d, want 32", len(emptyNTHash))
	}
}

// --- decryptDESHash tests ---

func TestDecryptDESHash_TooShort(t *testing.T) {
	_, err := decryptDESHash(make([]byte, 15), 500)
	if err == nil {
		t.Error("expected error for data < 16 bytes")
	}
}

func TestDecryptDESHash_RoundTrip(t *testing.T) {
	// Encrypt a known plaintext with DES using RID-derived keys, then decrypt
	rid := uint32(500)
	key1, key2 := desKeysFromRID(rid)

	plaintext := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	// Encrypt with DES
	block1, _ := des.NewCipher(key1)
	block2, _ := des.NewCipher(key2)
	encrypted := make([]byte, 16)
	block1.Encrypt(encrypted[:8], plaintext[:8])
	block2.Encrypt(encrypted[8:], plaintext[8:])

	// Decrypt
	decrypted, err := decryptDESHash(encrypted, rid)
	if err != nil {
		t.Fatalf("decryptDESHash failed: %v", err)
	}
	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, decrypted[i], plaintext[i])
		}
	}
}

func TestDecryptDESHash_DifferentRIDs(t *testing.T) {
	// Same ciphertext should decrypt differently with different RIDs
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i)
	}

	r1, _ := decryptDESHash(data, 500)
	r2, _ := decryptDESHash(data, 501)

	same := true
	for i := range r1 {
		if r1[i] != r2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different RIDs should produce different decryptions")
	}
}

// --- decryptSAMHashRC4 tests ---

func TestDecryptSAMHashRC4_TooShort(t *testing.T) {
	_, err := decryptSAMHashRC4(make([]byte, 19), 500, make([]byte, 16), samNTPASSWD)
	if err == nil {
		t.Error("expected error for data < 20 bytes")
	}
}

func TestDecryptSAMHashRC4_RoundTrip(t *testing.T) {
	// Create a synthetic SAM hash structure and verify the crypto pipeline
	rid := uint32(500)
	hashedBootKey := make([]byte, 16)
	for i := range hashedBootKey {
		hashedBootKey[i] = byte(i + 1)
	}

	// Create the inner DES-encrypted hash (encrypt a known plaintext)
	key1, key2 := desKeysFromRID(rid)
	plainHash := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	block1, _ := des.NewCipher(key1)
	block2, _ := des.NewCipher(key2)
	desEncrypted := make([]byte, 16)
	block1.Encrypt(desEncrypted[:8], plainHash[:8])
	block2.Encrypt(desEncrypted[8:], plainHash[8:])

	// RC4 encrypt: derive key the same way decryption does
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)
	h := md5.New()
	h.Write(hashedBootKey)
	h.Write(ridBytes)
	h.Write(samNTPASSWD)
	rc4Key := h.Sum(nil)
	c, _ := rc4.NewCipher(rc4Key)
	rc4Encrypted := make([]byte, 16)
	c.XORKeyStream(rc4Encrypted, desEncrypted)

	// Build SAM_HASH structure: pekID(2) + revision(2) + hash(16)
	hashData := make([]byte, 20)
	copy(hashData[4:], rc4Encrypted)

	// Decrypt
	result, err := decryptSAMHashRC4(hashData, rid, hashedBootKey, samNTPASSWD)
	if err != nil {
		t.Fatalf("decryptSAMHashRC4 failed: %v", err)
	}
	for i := range plainHash {
		if result[i] != plainHash[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, result[i], plainHash[i])
		}
	}
}

// --- decryptSAMHashAES tests ---

func TestDecryptSAMHashAES_TooShort(t *testing.T) {
	_, err := decryptSAMHashAES(make([]byte, 0x27), 500, make([]byte, 16))
	if err == nil {
		t.Error("expected error for data < 0x28 bytes")
	}
}

func TestDecryptSAMHashAES_MinimumSize(t *testing.T) {
	// Exactly 0x28 bytes: header + 16 bytes of encrypted data (hashData[0x18:0x28])
	// This should attempt decryption (not error on size check)
	hashData := make([]byte, 0x28)
	// The decryption will produce garbage but shouldn't panic
	_, err := decryptSAMHashAES(hashData, 500, make([]byte, 16))
	// May or may not error depending on AES validity, but shouldn't panic
	_ = err
}

func TestDecryptSAMHashAES_RoundTrip(t *testing.T) {
	rid := uint32(1001)
	hashedBootKey := make([]byte, 16)
	for i := range hashedBootKey {
		hashedBootKey[i] = byte(i + 0x10)
	}

	// Create a known plaintext hash (DES-encrypted inner layer)
	key1, key2 := desKeysFromRID(rid)
	plainHash := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	block1, _ := des.NewCipher(key1)
	block2, _ := des.NewCipher(key2)
	desEncrypted := make([]byte, 16)
	block1.Encrypt(desEncrypted[:8], plainHash[:8])
	block2.Encrypt(desEncrypted[8:], plainHash[8:])

	// AES-128-CBC encrypt the DES-encrypted hash
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 0x20)
	}
	aesBlock, _ := aes.NewCipher(hashedBootKey)
	mode := cipher.NewCBCEncrypter(aesBlock, salt)
	aesEncrypted := make([]byte, 16)
	mode.CryptBlocks(aesEncrypted, desEncrypted)

	// Build SAM_HASH_AES: pekID(2) + revision(2) + dataOffset(4) + salt(16) + encHash
	hashData := make([]byte, 0x18+len(aesEncrypted))
	copy(hashData[0x08:0x18], salt)
	copy(hashData[0x18:], aesEncrypted)

	result, err := decryptSAMHashAES(hashData, rid, hashedBootKey)
	if err != nil {
		t.Fatalf("decryptSAMHashAES failed: %v", err)
	}
	for i := range plainHash {
		if result[i] != plainHash[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, result[i], plainHash[i])
		}
	}
}

// --- decryptSAMHash dispatcher tests ---

func TestDecryptSAMHash_RC4Dispatch(t *testing.T) {
	// Revision 0x01 should use RC4 path
	_, err := decryptSAMHash(make([]byte, 10), 500, make([]byte, 16), samNTPASSWD, 0x01)
	if err == nil {
		t.Error("expected error for short data via RC4 path")
	}
}

func TestDecryptSAMHash_AESDispatch(t *testing.T) {
	// Revision 0x02 should use AES path
	_, err := decryptSAMHash(make([]byte, 10), 500, make([]byte, 16), samNTPASSWD, 0x02)
	if err == nil {
		t.Error("expected error for short data via AES path")
	}
}

// --- deriveHashedBootKeyRC4 tests ---

func TestDeriveHashedBootKeyRC4_TooShort(t *testing.T) {
	_, _, err := deriveHashedBootKeyRC4(make([]byte, 0x68+0x37), make([]byte, 16))
	if err == nil {
		t.Error("expected error for F value too short")
	}
}

func TestDeriveHashedBootKeyRC4_RoundTrip(t *testing.T) {
	bootKey := make([]byte, 16)
	for i := range bootKey {
		bootKey[i] = byte(i + 0x30)
	}

	// Construct a valid F value with RC4-encrypted key data
	fValue := make([]byte, 0xA0)
	fValue[0x68] = 0x01 // revision

	salt := fValue[0x70:0x80]
	for i := range salt {
		salt[i] = byte(i + 0x40)
	}

	// Create a known hashed boot key
	knownHBK := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	// Compute checksum: MD5(hbk + DIGITS + hbk + QWERTY)
	h2 := md5.New()
	h2.Write(knownHBK)
	h2.Write(samDIGITS)
	h2.Write(knownHBK)
	h2.Write(samQWERTY)
	checksum := h2.Sum(nil)

	// RC4 encrypt: key + checksum
	h := md5.New()
	h.Write(salt)
	h.Write(samQWERTY)
	h.Write(bootKey)
	h.Write(samDIGITS)
	rc4Key := h.Sum(nil)

	combined := make([]byte, 32)
	copy(combined[:16], knownHBK)
	copy(combined[16:], checksum)
	c, _ := rc4.NewCipher(rc4Key)
	c.XORKeyStream(combined, combined)

	copy(fValue[0x80:0x90], combined[:16])  // encrypted key
	copy(fValue[0x90:0xA0], combined[16:])  // encrypted checksum

	// Decrypt
	result, rev, err := deriveHashedBootKeyRC4(fValue, bootKey)
	if err != nil {
		t.Fatalf("deriveHashedBootKeyRC4 failed: %v", err)
	}
	if rev != 0x01 {
		t.Errorf("revision = 0x%02x, want 0x01", rev)
	}
	for i := range knownHBK {
		if result[i] != knownHBK[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, result[i], knownHBK[i])
		}
	}
}

func TestDeriveHashedBootKeyRC4_BadChecksum(t *testing.T) {
	bootKey := make([]byte, 16)
	fValue := make([]byte, 0xA0)
	fValue[0x68] = 0x01

	salt := fValue[0x70:0x80]
	for i := range salt {
		salt[i] = byte(i)
	}

	// RC4 encrypt garbage (will fail checksum)
	h := md5.New()
	h.Write(salt)
	h.Write(samQWERTY)
	h.Write(bootKey)
	h.Write(samDIGITS)
	rc4Key := h.Sum(nil)

	garbage := make([]byte, 32)
	for i := range garbage {
		garbage[i] = 0xFF
	}
	c, _ := rc4.NewCipher(rc4Key)
	c.XORKeyStream(garbage, garbage)
	copy(fValue[0x80:0xA0], garbage)

	_, _, err := deriveHashedBootKeyRC4(fValue, bootKey)
	if err == nil {
		t.Error("expected checksum mismatch error")
	}
}

// --- deriveHashedBootKeyAES tests ---

func TestDeriveHashedBootKeyAES_TooShort(t *testing.T) {
	_, _, err := deriveHashedBootKeyAES(make([]byte, 0x68+0x1F), make([]byte, 16))
	if err == nil {
		t.Error("expected error for F value too short")
	}
}

func TestDeriveHashedBootKeyAES_RoundTrip(t *testing.T) {
	bootKey := make([]byte, 16)
	for i := range bootKey {
		bootKey[i] = byte(i + 0x50)
	}

	// Known hashed boot key (16 bytes, will be padded to block-align)
	knownHBK := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}

	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 0x60)
	}

	// AES-128-CBC encrypt the known HBK
	block, _ := aes.NewCipher(bootKey)
	mode := cipher.NewCBCEncrypter(block, salt)
	encrypted := make([]byte, 16)
	mode.CryptBlocks(encrypted, knownHBK)

	// Build F value
	fValue := make([]byte, 0x88+len(encrypted))
	fValue[0x68] = 0x02 // revision
	binary.LittleEndian.PutUint32(fValue[0x74:0x78], uint32(len(encrypted))) // dataLen
	copy(fValue[0x78:0x88], salt)
	copy(fValue[0x88:], encrypted)

	result, rev, err := deriveHashedBootKeyAES(fValue, bootKey)
	if err != nil {
		t.Fatalf("deriveHashedBootKeyAES failed: %v", err)
	}
	if rev != 0x02 {
		t.Errorf("revision = 0x%02x, want 0x02", rev)
	}
	for i := range knownHBK {
		if result[i] != knownHBK[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, result[i], knownHBK[i])
		}
	}
}

// --- parseUserVValue tests ---

func TestParseUserVValue_TooShort(t *testing.T) {
	_, err := parseUserVValue(make([]byte, 0xCC+3), 500, make([]byte, 16), 0x01)
	if err == nil {
		t.Error("expected error for V value too short")
	}
}

func TestParseUserVValue_NameOutOfBounds(t *testing.T) {
	// Construct V value with name offset pointing past the end
	v := make([]byte, 0xCC+64)
	binary.LittleEndian.PutUint32(v[0x0C:0x10], 0xFFFF) // name offset (relative to 0xCC)
	binary.LittleEndian.PutUint32(v[0x10:0x14], 10)      // name length

	_, err := parseUserVValue(v, 500, make([]byte, 16), 0x01)
	if err == nil {
		t.Error("expected error for name out of bounds")
	}
}

func TestParseUserVValue_ValidStructure(t *testing.T) {
	// Construct a minimal V value with a known username
	// Username "Test" in UTF-16LE
	nameUTF16 := []byte{0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00}

	v := make([]byte, 0xCC+len(nameUTF16)+64)

	// Name offset (relative, added to 0xCC) = 0, length = 8
	binary.LittleEndian.PutUint32(v[0x0C:0x10], 0)
	binary.LittleEndian.PutUint32(v[0x10:0x14], uint32(len(nameUTF16)))

	// NT hash offset + length = 0 (will use empty hash)
	binary.LittleEndian.PutUint32(v[0xA8:0xAC], 0)
	binary.LittleEndian.PutUint32(v[0xAC:0xB0], 0)

	// LM hash offset + length = 0 (will use empty hash)
	binary.LittleEndian.PutUint32(v[0x9C:0xA0], 0)
	binary.LittleEndian.PutUint32(v[0xA0:0xA4], 0)

	// Copy username to data area (starts at 0xCC)
	copy(v[0xCC:], nameUTF16)

	result, err := parseUserVValue(v, 500, make([]byte, 16), 0x01)
	if err != nil {
		t.Fatalf("parseUserVValue failed: %v", err)
	}
	if result.username != "Test" {
		t.Errorf("username = %q, want %q", result.username, "Test")
	}
	if result.rid != 500 {
		t.Errorf("rid = %d, want 500", result.rid)
	}
	if result.lmHash != emptyLMHash {
		t.Errorf("lmHash = %q, want empty LM hash", result.lmHash)
	}
	if result.ntHash != emptyNTHash {
		t.Errorf("ntHash = %q, want empty NT hash", result.ntHash)
	}
}

func TestParseUserVValue_WithHashes(t *testing.T) {
	// Construct a V value that has actual hash data (length > 4) to exercise
	// the decryption branches for both NT and LM hashes.
	rid := uint32(500)
	hashedBootKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	// Known plaintext hash (what we expect after decryption)
	plainHash := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	// Build encrypted hash data for RC4 (revision 0x01):
	// SAM_HASH: pekID(2) + revision(2) + encHash(16) = 20 bytes
	key1, key2 := desKeysFromRID(rid)
	block1, _ := des.NewCipher(key1)
	block2, _ := des.NewCipher(key2)
	desEnc := make([]byte, 16)
	block1.Encrypt(desEnc[:8], plainHash[:8])
	block2.Encrypt(desEnc[8:], plainHash[8:])

	// RC4 encrypt with NTPASSWORD
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)
	h := md5.New()
	h.Write(hashedBootKey)
	h.Write(ridBytes)
	h.Write(samNTPASSWD)
	rc4Key := h.Sum(nil)
	c, _ := rc4.NewCipher(rc4Key)
	rc4Enc := make([]byte, 16)
	c.XORKeyStream(rc4Enc, desEnc)
	ntHashData := make([]byte, 20)
	copy(ntHashData[4:], rc4Enc)

	// RC4 encrypt with LMPASSWORD
	h2 := md5.New()
	h2.Write(hashedBootKey)
	h2.Write(ridBytes)
	h2.Write(samLMPASSWD)
	rc4KeyLM := h2.Sum(nil)
	c2, _ := rc4.NewCipher(rc4KeyLM)
	rc4EncLM := make([]byte, 16)
	c2.XORKeyStream(rc4EncLM, desEnc)
	lmHashData := make([]byte, 20)
	copy(lmHashData[4:], rc4EncLM)

	// Username "Admin" in UTF-16LE
	nameUTF16 := []byte{0x41, 0x00, 0x64, 0x00, 0x6D, 0x00, 0x69, 0x00, 0x6E, 0x00}

	// Build V value: header (0xCC bytes) + data area
	// Data layout after 0xCC: [name(10)] [lmHash(20)] [ntHash(20)]
	nameRelOff := uint32(0) // relative to 0xCC
	lmRelOff := uint32(len(nameUTF16))
	ntRelOff := lmRelOff + uint32(len(lmHashData))

	dataSize := len(nameUTF16) + len(lmHashData) + len(ntHashData)
	v := make([]byte, 0xCC+dataSize)

	// Name: offset at v[0x0C], length at v[0x10]
	binary.LittleEndian.PutUint32(v[0x0C:0x10], nameRelOff)
	binary.LittleEndian.PutUint32(v[0x10:0x14], uint32(len(nameUTF16)))

	// LM hash: offset at v[0x9C], length at v[0xA0]
	binary.LittleEndian.PutUint32(v[0x9C:0xA0], lmRelOff)
	binary.LittleEndian.PutUint32(v[0xA0:0xA4], uint32(len(lmHashData)))

	// NT hash: offset at v[0xA8], length at v[0xAC]
	binary.LittleEndian.PutUint32(v[0xA8:0xAC], ntRelOff)
	binary.LittleEndian.PutUint32(v[0xAC:0xB0], uint32(len(ntHashData)))

	// Copy data
	copy(v[0xCC:], nameUTF16)
	copy(v[0xCC+lmRelOff:], lmHashData)
	copy(v[0xCC+ntRelOff:], ntHashData)

	result, err := parseUserVValue(v, rid, hashedBootKey, 0x01)
	if err != nil {
		t.Fatalf("parseUserVValue failed: %v", err)
	}
	if result.username != "Admin" {
		t.Errorf("username = %q, want %q", result.username, "Admin")
	}
	if result.rid != 500 {
		t.Errorf("rid = %d, want 500", result.rid)
	}
	expectedHash := hex.EncodeToString(plainHash)
	if result.ntHash != expectedHash {
		t.Errorf("ntHash = %q, want %q", result.ntHash, expectedHash)
	}
	if result.lmHash != expectedHash {
		t.Errorf("lmHash = %q, want %q", result.lmHash, expectedHash)
	}
}

// --- SAM constant validation ---

func TestSAMConstants_NonEmpty(t *testing.T) {
	if len(samQWERTY) == 0 {
		t.Error("samQWERTY should not be empty")
	}
	if len(samDIGITS) == 0 {
		t.Error("samDIGITS should not be empty")
	}
	if len(samNTPASSWD) == 0 {
		t.Error("samNTPASSWD should not be empty")
	}
	if len(samLMPASSWD) == 0 {
		t.Error("samLMPASSWD should not be empty")
	}
}

func TestSAMConstants_NullTerminated(t *testing.T) {
	// SAM constants should be null-terminated (Windows convention)
	if samQWERTY[len(samQWERTY)-1] != 0x00 {
		t.Error("samQWERTY should be null-terminated")
	}
	if samDIGITS[len(samDIGITS)-1] != 0x00 {
		t.Error("samDIGITS should be null-terminated")
	}
	if samNTPASSWD[len(samNTPASSWD)-1] != 0x00 {
		t.Error("samNTPASSWD should be null-terminated")
	}
	if samLMPASSWD[len(samLMPASSWD)-1] != 0x00 {
		t.Error("samLMPASSWD should be null-terminated")
	}
}

// --- End-to-end crypto pipeline test ---

func TestFullSAMDecryptionPipeline_RC4(t *testing.T) {
	// Simulate a complete SAM hash decryption:
	// 1. Start with known plaintext NTLM hash
	// 2. DES encrypt with RID-derived keys
	// 3. RC4 encrypt the DES-encrypted hash
	// 4. Decrypt through the full pipeline
	// 5. Verify we get the original hash back

	rid := uint32(500)
	hashedBootKey := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	originalHash := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	// DES encrypt
	key1, key2 := desKeysFromRID(rid)
	block1, _ := des.NewCipher(key1)
	block2, _ := des.NewCipher(key2)
	desEnc := make([]byte, 16)
	block1.Encrypt(desEnc[:8], originalHash[:8])
	block2.Encrypt(desEnc[8:], originalHash[8:])

	// RC4 encrypt
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)
	h := md5.New()
	h.Write(hashedBootKey)
	h.Write(ridBytes)
	h.Write(samNTPASSWD)
	rc4Key := h.Sum(nil)
	c, _ := rc4.NewCipher(rc4Key)
	rc4Enc := make([]byte, 16)
	c.XORKeyStream(rc4Enc, desEnc)

	// Build SAM hash structure
	hashData := make([]byte, 20)
	copy(hashData[4:], rc4Enc)

	// Decrypt through the dispatcher
	result, err := decryptSAMHash(hashData, rid, hashedBootKey, samNTPASSWD, 0x01)
	if err != nil {
		t.Fatalf("Full pipeline failed: %v", err)
	}

	for i := range originalHash {
		if result[i] != originalHash[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, result[i], originalHash[i])
		}
	}
}

func TestFullSAMDecryptionPipeline_AES(t *testing.T) {
	rid := uint32(1001)
	hashedBootKey := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}
	originalHash := []byte{0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	// DES encrypt
	key1, key2 := desKeysFromRID(rid)
	block1, _ := des.NewCipher(key1)
	block2, _ := des.NewCipher(key2)
	desEnc := make([]byte, 16)
	block1.Encrypt(desEnc[:8], originalHash[:8])
	block2.Encrypt(desEnc[8:], originalHash[8:])

	// AES-128-CBC encrypt
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 0x70)
	}
	aesBlock, _ := aes.NewCipher(hashedBootKey)
	mode := cipher.NewCBCEncrypter(aesBlock, salt)
	aesEnc := make([]byte, 16)
	mode.CryptBlocks(aesEnc, desEnc)

	// Build SAM_HASH_AES structure
	hashData := make([]byte, 0x18+len(aesEnc))
	copy(hashData[0x08:0x18], salt)
	copy(hashData[0x18:], aesEnc)

	result, err := decryptSAMHash(hashData, rid, hashedBootKey, samNTPASSWD, 0x02)
	if err != nil {
		t.Fatalf("Full AES pipeline failed: %v", err)
	}

	for i := range originalHash {
		if result[i] != originalHash[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, result[i], originalHash[i])
		}
	}
}

// --- Padding path tests ---

func TestDeriveHashedBootKeyAES_UnalignedPadding(t *testing.T) {
	// Test the padding branch: encData length not aligned to AES block size.
	// Build F value where dataLen is 20 (not a multiple of 16).
	bootKey := make([]byte, 16)
	for i := range bootKey {
		bootKey[i] = byte(i + 0x70)
	}

	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 0x80)
	}

	// Encrypt 32 bytes (2 blocks) of known data
	knownHBK := make([]byte, 32)
	for i := range knownHBK {
		knownHBK[i] = byte(i + 0xA0)
	}
	block, _ := aes.NewCipher(bootKey)
	modeEnc := cipher.NewCBCEncrypter(block, salt)
	encrypted := make([]byte, 32)
	modeEnc.CryptBlocks(encrypted, knownHBK)

	// Build F value with dataLen=20 (unaligned). The function should pad to 32.
	dataLen := uint32(20)
	fValue := make([]byte, 0x88+32)
	binary.LittleEndian.PutUint32(fValue[0x74:0x78], dataLen)
	copy(fValue[0x78:0x88], salt)
	// Copy only first 20 bytes of encrypted data — rest is zeros
	copy(fValue[0x88:0x88+20], encrypted[:20])

	// Should not panic, and should return 16 bytes
	result, rev, err := deriveHashedBootKeyAES(fValue, bootKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rev != 0x02 {
		t.Errorf("expected revision 0x02, got 0x%02x", rev)
	}
	if len(result) != 16 {
		t.Errorf("expected 16-byte result, got %d", len(result))
	}
}

func TestDecryptSAMHashAES_UnalignedPadding(t *testing.T) {
	// Test the padding branch: encrypted hash length not aligned to AES block size.
	rid := uint32(1001)
	hashedBootKey := make([]byte, 16)
	for i := range hashedBootKey {
		hashedBootKey[i] = byte(i + 0x30)
	}

	// Create DES-encrypted inner layer (16 bytes)
	key1, key2 := desKeysFromRID(rid)
	plainHash := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	block1, _ := des.NewCipher(key1)
	block2, _ := des.NewCipher(key2)
	desEncrypted := make([]byte, 16)
	block1.Encrypt(desEncrypted[:8], plainHash[:8])
	block2.Encrypt(desEncrypted[8:], plainHash[8:])

	// AES encrypt with 32 bytes (pad the 16 DES bytes to 32)
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 0x40)
	}
	aesBlock, _ := aes.NewCipher(hashedBootKey)
	aesMode := cipher.NewCBCEncrypter(aesBlock, salt)
	padded := make([]byte, 32)
	copy(padded, desEncrypted)
	aesEncrypted := make([]byte, 32)
	aesMode.CryptBlocks(aesEncrypted, padded)

	// Build SAM_HASH_AES with only 20 bytes of encrypted data (triggers padding)
	hashData := make([]byte, 0x18+20)
	copy(hashData[0x08:0x18], salt)
	copy(hashData[0x18:], aesEncrypted[:20])

	// Should not panic — padding will add zeros but decryption will produce different result
	_, err := decryptSAMHashAES(hashData, rid, hashedBootKey)
	// Error is acceptable (padding zeros corrupt the ciphertext), but no panic
	_ = err
}

func TestDecryptSAMHashAES_EncHashTooShort(t *testing.T) {
	// hashData is >= 0x28 but the encrypted hash portion (hashData[0x18:]) is < 16 bytes
	hashData := make([]byte, 0x24) // 0x24 - 0x18 = 12 bytes of enc data (< 16)
	_, err := decryptSAMHashAES(hashData, 500, make([]byte, 16))
	if err == nil {
		t.Error("expected error for encrypted hash < 16 bytes")
	}
}
