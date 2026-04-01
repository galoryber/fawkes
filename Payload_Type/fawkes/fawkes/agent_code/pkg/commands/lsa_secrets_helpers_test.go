package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// --- lsaSHA256Rounds tests ---

func TestLsaSHA256Rounds_SingleRound(t *testing.T) {
	key := []byte("testkey")
	data := []byte("testdata")
	result := lsaSHA256Rounds(key, data, 1)
	if len(result) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(result))
	}

	// Manual verification: SHA256(key + data)
	h := sha256.New()
	h.Write(key)
	h.Write(data)
	expected := h.Sum(nil)
	if !lsaBytesEqual(result, expected) {
		t.Errorf("single round mismatch")
	}
}

func TestLsaSHA256Rounds_MultipleRounds(t *testing.T) {
	key := []byte("key")
	data := []byte("data")
	result := lsaSHA256Rounds(key, data, 3)
	if len(result) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(result))
	}

	// Manual: 3 rounds of write(key)+write(data) into single SHA256 context
	h := sha256.New()
	for i := 0; i < 3; i++ {
		h.Write(key)
		h.Write(data)
	}
	expected := h.Sum(nil)
	if !lsaBytesEqual(result, expected) {
		t.Errorf("multi-round mismatch")
	}
}

func TestLsaSHA256Rounds_ZeroRounds(t *testing.T) {
	result := lsaSHA256Rounds([]byte("k"), []byte("d"), 0)
	// Zero rounds = just SHA256 of empty input
	h := sha256.New()
	expected := h.Sum(nil)
	if !lsaBytesEqual(result, expected) {
		t.Errorf("zero rounds should return SHA256 of empty")
	}
}

func TestLsaSHA256Rounds_EmptyInputs(t *testing.T) {
	result := lsaSHA256Rounds(nil, nil, 5)
	if len(result) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(result))
	}
}

func TestLsaSHA256Rounds_LargeRoundCount(t *testing.T) {
	result := lsaSHA256Rounds([]byte("boot"), []byte("enc"), 1000)
	if len(result) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(result))
	}
	// Verify deterministic
	result2 := lsaSHA256Rounds([]byte("boot"), []byte("enc"), 1000)
	if !lsaBytesEqual(result, result2) {
		t.Error("results should be deterministic")
	}
}

// --- lsaAESDecryptECB tests ---

func TestLsaAESDecryptECB_InvalidKeyLength(t *testing.T) {
	_, err := lsaAESDecryptECB([]byte("short"), []byte("data"))
	if err == nil {
		t.Error("expected error for short key")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLsaAESDecryptECB_SingleBlock(t *testing.T) {
	// Encrypt a known block, then verify decryption
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := make([]byte, 16)
	for i := range plaintext {
		plaintext[i] = byte(0x41 + i)
	}

	// Encrypt with AES-ECB (CBC with zero IV for one block = ECB)
	block, _ := aes.NewCipher(key)
	zeroIV := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, zeroIV)
	ciphertext := make([]byte, 16)
	mode.CryptBlocks(ciphertext, plaintext)

	// Decrypt
	result, err := lsaAESDecryptECB(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !lsaBytesEqual(result, plaintext) {
		t.Errorf("decrypted != original\ngot:  %x\nwant: %x", result, plaintext)
	}
}

func TestLsaAESDecryptECB_MultipleBlocks(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}

	// 3 blocks of data
	plaintext := make([]byte, 48)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// Encrypt each block independently (ECB mode)
	block, _ := aes.NewCipher(key)
	zeroIV := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, 48)
	for i := 0; i < 48; i += 16 {
		mode := cipher.NewCBCEncrypter(block, zeroIV)
		mode.CryptBlocks(ciphertext[i:i+16], plaintext[i:i+16])
	}

	result, err := lsaAESDecryptECB(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !lsaBytesEqual(result, plaintext) {
		t.Errorf("multi-block decrypted != original")
	}
}

func TestLsaAESDecryptECB_PartialBlock(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Data not a multiple of block size (20 bytes = 1 full + 4 partial)
	data := make([]byte, 20)
	for i := range data {
		data[i] = byte(0xAA)
	}

	// Should not error — handles partial blocks
	result, err := lsaAESDecryptECB(key, data)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if len(result) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(result))
	}
}

func TestLsaAESDecryptECB_EmptyData(t *testing.T) {
	key := make([]byte, 32)
	result, err := lsaAESDecryptECB(key, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(result))
	}
}

// --- lsaUTF16ToString tests ---

func TestLsaUTF16ToString_ASCII(t *testing.T) {
	// "Hello" in UTF-16LE
	data := []byte{0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00}
	result := lsaUTF16ToString(data)
	if result != "Hello" {
		t.Errorf("expected 'Hello', got %q", result)
	}
}

func TestLsaUTF16ToString_NullTerminated(t *testing.T) {
	// "Hi" + null + garbage
	data := []byte{0x48, 0x00, 0x69, 0x00, 0x00, 0x00, 0xFF, 0xFF}
	result := lsaUTF16ToString(data)
	if result != "Hi" {
		t.Errorf("expected 'Hi', got %q", result)
	}
}

func TestLsaUTF16ToString_Empty(t *testing.T) {
	result := lsaUTF16ToString([]byte{})
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestLsaUTF16ToString_SingleByte(t *testing.T) {
	result := lsaUTF16ToString([]byte{0x41})
	if result != "" {
		t.Errorf("expected empty for single byte, got %q", result)
	}
}

func TestLsaUTF16ToString_OddLength(t *testing.T) {
	// 5 bytes — should truncate to 4 and decode 2 chars
	data := []byte{0x41, 0x00, 0x42, 0x00, 0xFF}
	result := lsaUTF16ToString(data)
	if result != "AB" {
		t.Errorf("expected 'AB', got %q", result)
	}
}

func TestLsaUTF16ToString_Unicode(t *testing.T) {
	// "Ä" (U+00C4) in UTF-16LE
	data := []byte{0xC4, 0x00}
	result := lsaUTF16ToString(data)
	if result != "Ä" {
		t.Errorf("expected 'Ä', got %q", result)
	}
}

func TestLsaUTF16ToString_JustNull(t *testing.T) {
	data := []byte{0x00, 0x00}
	result := lsaUTF16ToString(data)
	if result != "" {
		t.Errorf("expected empty for null-only, got %q", result)
	}
}

// --- lsaExtractPrintable tests ---

func TestLsaExtractPrintable_AllPrintable(t *testing.T) {
	result := lsaExtractPrintable([]byte("Hello World"))
	if result != "Hello World" {
		t.Errorf("expected 'Hello World', got %q", result)
	}
}

func TestLsaExtractPrintable_MixedBinary(t *testing.T) {
	data := []byte{0x00, 0x01, 'P', 'a', 's', 's', 0xFF, 'w', 'o', 'r', 'd', 0x00}
	result := lsaExtractPrintable(data)
	if result != "Password" {
		t.Errorf("expected 'Password', got %q", result)
	}
}

func TestLsaExtractPrintable_TooFewPrintable(t *testing.T) {
	data := []byte{0x00, 'A', 0x01, 'B', 0x02, 'C', 0x00}
	result := lsaExtractPrintable(data)
	if result != "" {
		t.Errorf("expected empty for <4 printable chars, got %q", result)
	}
}

func TestLsaExtractPrintable_ExactlyFour(t *testing.T) {
	data := []byte{0x00, 'A', 'B', 'C', 'D', 0x00}
	result := lsaExtractPrintable(data)
	if result != "ABCD" {
		t.Errorf("expected 'ABCD', got %q", result)
	}
}

func TestLsaExtractPrintable_AllBinary(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}
	result := lsaExtractPrintable(data)
	if result != "" {
		t.Errorf("expected empty for all binary, got %q", result)
	}
}

func TestLsaExtractPrintable_EmptyInput(t *testing.T) {
	result := lsaExtractPrintable([]byte{})
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

// --- lsaFormatSecret tests ---

func TestLsaFormatSecret_Empty(t *testing.T) {
	result := lsaFormatSecret("test", []byte{})
	if result != "    (empty)\n" {
		t.Errorf("expected empty marker, got %q", result)
	}
}

func TestLsaFormatSecret_ServiceAccount(t *testing.T) {
	// "_SC_MyService" with password "Password123" in UTF-16LE
	password := utf16LEEncode("Password123")
	result := lsaFormatSecret("_SC_MyService", password)
	if !strings.Contains(result, "Service: MyService") {
		t.Errorf("expected service name, got %q", result)
	}
	if !strings.Contains(result, "Password: Password123") {
		t.Errorf("expected password, got %q", result)
	}
}

func TestLsaFormatSecret_MachineAccount(t *testing.T) {
	secret := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	result := lsaFormatSecret("$MACHINE.ACC", secret)
	if !strings.Contains(result, "Machine Account Password") {
		t.Errorf("expected machine account header, got %q", result)
	}
	if !strings.Contains(result, "4 bytes") {
		t.Errorf("expected byte count, got %q", result)
	}
	if !strings.Contains(result, "aabbccdd") {
		t.Errorf("expected hex dump, got %q", result)
	}
}

func TestLsaFormatSecret_DPAPISystem(t *testing.T) {
	// version(4) + userKey(20) + machineKey(20)
	secret := make([]byte, 44)
	secret[0] = 0x01 // version
	for i := 4; i < 24; i++ {
		secret[i] = byte(i) // user key
	}
	for i := 24; i < 44; i++ {
		secret[i] = byte(i + 0x40) // machine key
	}

	result := lsaFormatSecret("DPAPI_SYSTEM", secret)
	if !strings.Contains(result, "DPAPI User Key:") {
		t.Errorf("expected user key, got %q", result)
	}
	if !strings.Contains(result, "DPAPI Machine Key:") {
		t.Errorf("expected machine key, got %q", result)
	}
}

func TestLsaFormatSecret_DPAPISystem_TooShort(t *testing.T) {
	secret := make([]byte, 20) // Less than 44
	result := lsaFormatSecret("DPAPI_SYSTEM", secret)
	if !strings.Contains(result, "Raw (20 bytes)") {
		t.Errorf("expected raw format for short DPAPI, got %q", result)
	}
}

func TestLsaFormatSecret_NLKM(t *testing.T) {
	secret := make([]byte, 64)
	result := lsaFormatSecret("NL$KM", secret)
	if !strings.Contains(result, "Cache Encryption Key") {
		t.Errorf("expected cache key header, got %q", result)
	}
	if !strings.Contains(result, "64 bytes") {
		t.Errorf("expected byte count, got %q", result)
	}
}

func TestLsaFormatSecret_DefaultPassword(t *testing.T) {
	password := utf16LEEncode("AutoLogon!")
	result := lsaFormatSecret("DefaultPassword", password)
	if !strings.Contains(result, "Auto-Logon Password: AutoLogon!") {
		t.Errorf("expected auto-logon password, got %q", result)
	}
}

func TestLsaFormatSecret_Unknown(t *testing.T) {
	secret := []byte{0x00, 0x01, 'T', 'e', 's', 't', 'V', 'a', 'l', 'u', 'e', 0xFF}
	result := lsaFormatSecret("CustomSecret", secret)
	if !strings.Contains(result, "Raw (12 bytes)") {
		t.Errorf("expected raw format, got %q", result)
	}
	if !strings.Contains(result, "Printable: TestValue") {
		t.Errorf("expected printable extraction, got %q", result)
	}
}

func TestLsaFormatSecret_UnknownNoPrintable(t *testing.T) {
	secret := []byte{0x00, 0x01, 0x02, 0x03}
	result := lsaFormatSecret("BinaryOnly", secret)
	if !strings.Contains(result, "Raw (4 bytes)") {
		t.Errorf("expected raw format, got %q", result)
	}
	if strings.Contains(result, "Printable") {
		t.Errorf("should not have printable for all-binary data")
	}
}

// --- lsaDecryptSecret tests ---

func TestLsaDecryptSecret_TooShort(t *testing.T) {
	_, err := lsaDecryptSecret(make([]byte, 30), make([]byte, 32))
	if err == nil {
		t.Error("expected error for short data")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLsaDecryptSecret_ValidStructure(t *testing.T) {
	// Build a valid LSA_SECRET structure
	lsaKey := make([]byte, 32)
	for i := range lsaKey {
		lsaKey[i] = byte(i)
	}

	// Build encrypted data:
	// header(28 bytes) + salt(32 bytes) + encrypted_blob
	header := make([]byte, 28) // version + keyID + algo + flags
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 0x10)
	}

	// Create the plaintext that lsaDecryptSecret expects after AES decryption:
	// LSA_SECRET_BLOB: length(4) + unknown(12) + secret(rest)
	secretContent := []byte("MySecretData")
	blobPlain := make([]byte, 16+len(secretContent))
	binary.LittleEndian.PutUint32(blobPlain[0:4], uint32(len(secretContent)))
	copy(blobPlain[16:], secretContent)

	// Derive the same key that lsaDecryptSecret will derive
	tmpKey := lsaSHA256Rounds(lsaKey, salt, 1000)

	// Encrypt the blob using the same AES-ECB method
	encrypted, err := lsaAESEncryptECB(tmpKey, blobPlain)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Build the full data
	data := make([]byte, 0, 28+32+len(encrypted))
	data = append(data, header...)
	data = append(data, salt...)
	data = append(data, encrypted...)

	// Decrypt
	result, err := lsaDecryptSecret(data, lsaKey)
	if err != nil {
		t.Fatalf("lsaDecryptSecret failed: %v", err)
	}

	if string(result) != "MySecretData" {
		t.Errorf("expected 'MySecretData', got %q", string(result))
	}
}

func TestLsaDecryptSecret_BlobTooShort(t *testing.T) {
	lsaKey := make([]byte, 32)
	// Build data where after decryption, the blob is < 16 bytes
	// This requires careful construction: 28 header + 32 salt + <16 encrypted
	// The encrypted data must decrypt to something < 16 bytes
	header := make([]byte, 28)
	salt := make([]byte, 32)
	// Minimal encrypted data (1 AES block = 16 bytes, decrypts to something)
	// But the decrypted result will be 16 bytes exactly, which passes the check
	// To get "too short", we'd need the decrypted data to be < 16 bytes,
	// but AES always outputs full blocks. So this path is hard to trigger.
	// Test that we don't crash with minimal valid input.
	tmpKey := lsaSHA256Rounds(lsaKey, salt, 1000)
	block := make([]byte, 16)
	enc, _ := lsaAESEncryptECB(tmpKey, block)
	data := make([]byte, 0, 28+32+len(enc))
	data = append(data, header...)
	data = append(data, salt...)
	data = append(data, enc...)

	result, err := lsaDecryptSecret(data, lsaKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With secretLen=0 from zeros, returns plaintext[16:] which is empty
	_ = result
}

// --- lsaParseCachedCred tests ---

func TestLsaParseCachedCred_TooShort(t *testing.T) {
	_, err := lsaParseCachedCred(make([]byte, 50), make([]byte, 32), 10240)
	if err == nil {
		t.Error("expected error for short data")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLsaParseCachedCred_EmptySlot(t *testing.T) {
	data := make([]byte, 200)
	// userNameLen = 0 → empty cache slot
	result, err := lsaParseCachedCred(data, make([]byte, 32), 10240)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil for empty cache slot")
	}
}

func TestLsaParseCachedCred_InvalidEntry(t *testing.T) {
	data := make([]byte, 200)
	// userNameLen > 0 but valid = 0
	binary.LittleEndian.PutUint16(data[0:2], 10)  // userNameLen
	binary.LittleEndian.PutUint32(data[48:52], 0) // valid = 0
	result, err := lsaParseCachedCred(data, make([]byte, 32), 10240)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil for invalid entry (valid=0)")
	}
}

func TestLsaParseCachedCred_ValidEntry(t *testing.T) {
	// Build a valid NL_RECORD with encrypted cached credential
	username := "administrator"
	domain := "CORP"

	userUTF16 := utf16LEEncode(username)
	domainUTF16 := utf16LEEncode(domain)

	// NL_RECORD header (100 bytes)
	header := make([]byte, 100)
	binary.LittleEndian.PutUint16(header[0:2], uint16(len(userUTF16)))   // userNameLen
	binary.LittleEndian.PutUint16(header[2:4], uint16(len(domainUTF16))) // domainNameLen
	binary.LittleEndian.PutUint32(header[48:52], 1)                      // valid
	binary.LittleEndian.PutUint32(header[52:56], 0)                      // entryIterCount (use global)

	// IV (16 bytes at offset 68)
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	copy(header[68:84], iv)

	// Build plaintext that goes after the header (encrypted):
	// MSCacheV2Hash(16) + username(UTF-16) + pad4 + domain(UTF-16)
	dcc2Hash := make([]byte, 16)
	for i := range dcc2Hash {
		dcc2Hash[i] = byte(0xAA + i)
	}

	plainOffset := 16 + len(userUTF16)
	// Align to 4 bytes
	aligned := (plainOffset + 3) & ^3
	plaintext := make([]byte, aligned+len(domainUTF16))
	copy(plaintext[0:16], dcc2Hash)
	copy(plaintext[16:16+len(userUTF16)], userUTF16)
	copy(plaintext[aligned:], domainUTF16)

	// NL$KM key (32 bytes) — cache key is nlkm[16:32]
	nlkm := make([]byte, 32)
	for i := range nlkm {
		nlkm[i] = byte(i + 0x30)
	}
	cacheKey := nlkm[16:32]

	// Encrypt plaintext with AES-128-CBC
	// Pad to block size
	encLen := len(plaintext)
	if encLen%aes.BlockSize != 0 {
		padded := make([]byte, ((encLen+aes.BlockSize-1)/aes.BlockSize)*aes.BlockSize)
		copy(padded, plaintext)
		plaintext = padded
	}

	block, err := aes.NewCipher(cacheKey)
	if err != nil {
		t.Fatalf("AES init: %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(plaintext))
	mode.CryptBlocks(encrypted, plaintext)

	// Combine header + encrypted data
	data := make([]byte, 0, 100+len(encrypted))
	data = append(data, header...)
	data = append(data, encrypted...)

	result, err := lsaParseCachedCred(data, nlkm, 10240)
	if err != nil {
		t.Fatalf("lsaParseCachedCred failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
			return // unreachable, helps staticcheck
	}

	if result.username != username {
		t.Errorf("username = %q, want %q", result.username, username)
	}
	if result.domain != domain {
		t.Errorf("domain = %q, want %q", result.domain, domain)
	}
	expectedHash := hex.EncodeToString(dcc2Hash)
	if result.hash != expectedHash {
		t.Errorf("hash = %q, want %q", result.hash, expectedHash)
	}
	expectedHashcat := "$DCC2$10240#administrator#" + expectedHash
	if result.hashcat != expectedHashcat {
		t.Errorf("hashcat = %q, want %q", result.hashcat, expectedHashcat)
	}
}

func TestLsaParseCachedCred_EntryIterCount(t *testing.T) {
	// Build minimal valid entry with entry-specific iteration count
	header := make([]byte, 100)
	binary.LittleEndian.PutUint16(header[0:2], 2)      // userNameLen (1 UTF-16 char)
	binary.LittleEndian.PutUint16(header[2:4], 2)      // domainNameLen
	binary.LittleEndian.PutUint32(header[48:52], 1)    // valid
	binary.LittleEndian.PutUint32(header[52:56], 5000) // entryIterCount overrides global

	iv := make([]byte, 16)
	copy(header[68:84], iv)

	nlkm := make([]byte, 32)
	cacheKey := nlkm[16:32]

	// Plaintext: hash(16) + username(2) + pad(2) + domain(2)
	plaintext := make([]byte, 32) // padded to block size
	plaintext[16] = 'A'           // username 'A' in UTF-16LE

	block, _ := aes.NewCipher(cacheKey)
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, 32)
	mode.CryptBlocks(encrypted, plaintext)

	data := make([]byte, 0, 100+len(encrypted))
	data = append(data, header...)
	data = append(data, encrypted...)

	result, err := lsaParseCachedCred(data, nlkm, 10240)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
			return // unreachable, helps staticcheck
	}
	// Should use entry iteration count (5000), not global (10240)
	if !strings.Contains(result.hashcat, "$DCC2$5000#") {
		t.Errorf("expected iteration count 5000, got %q", result.hashcat)
	}
}

func TestLsaParseCachedCred_EncryptedDataTooShort(t *testing.T) {
	header := make([]byte, 100)
	binary.LittleEndian.PutUint16(header[0:2], 100) // userNameLen = 100
	binary.LittleEndian.PutUint32(header[48:52], 1) // valid

	// Only 10 bytes of encrypted data, but needs 16 + 100 = 116
	data := make([]byte, 110)
	copy(data, header)

	_, err := lsaParseCachedCred(data, make([]byte, 32), 10240)
	if err == nil {
		t.Error("expected error for short encrypted data")
	}
}

// --- Helper functions for tests ---

// lsaBytesEqual compares two byte slices for equality — test helper
func lsaBytesEqual(a, b []byte) bool {
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

// utf16LEEncode converts a string to UTF-16LE bytes
func utf16LEEncode(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, c := range s {
		result[i*2] = byte(c)
		result[i*2+1] = byte(c >> 8)
	}
	return result
}

// lsaAESEncryptECB encrypts using AES-256-ECB (CBC with zero IV per block) — test helper.
// Returns full-block ciphertext (zero-padded if input not block-aligned).
func lsaAESEncryptECB(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Pad to block size
	padLen := len(data)
	if padLen%aes.BlockSize != 0 {
		padLen = ((padLen + aes.BlockSize - 1) / aes.BlockSize) * aes.BlockSize
	}
	padded := make([]byte, padLen)
	copy(padded, data)

	ciphertext := make([]byte, padLen)
	zeroIV := make([]byte, aes.BlockSize)
	for i := 0; i < padLen; i += aes.BlockSize {
		mode := cipher.NewCBCEncrypter(block, zeroIV)
		mode.CryptBlocks(ciphertext[i:i+16], padded[i:i+16])
	}
	return ciphertext, nil
}
