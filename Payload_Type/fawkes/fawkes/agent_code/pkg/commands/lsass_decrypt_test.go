package commands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"strings"
	"testing"
)

// All decryption tests run against synthetic ciphertext built locally with
// crypto/aes + crypto/des, so the round-trips are deterministic and don't
// require a Windows host or live LSASS data.

// encryptAES_CFB encrypts plaintext with AES-256-CFB using the same primitives
// the production decryptor consumes. The IV slice is sized to lsaAESIVLen.
func encryptAES_CFB(t *testing.T, plaintext, key, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	ivCopy := make([]byte, lsaAESIVLen)
	copy(ivCopy, iv[:lsaAESIVLen])
	out := make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(block, ivCopy)
	stream.XORKeyStream(out, plaintext)
	return out
}

// encryptTDES_CBC encrypts plaintext with 3DES-CBC using the first 8 bytes of
// `iv`. The plaintext must be a multiple of the 3DES block size (8).
func encryptTDES_CBC(t *testing.T, plaintext, key, iv []byte) []byte {
	t.Helper()
	if len(plaintext)%lsaTDESBlockSz != 0 {
		t.Fatalf("3DES test plaintext must be aligned to 8 bytes, got %d", len(plaintext))
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		t.Fatalf("des.NewTripleDESCipher: %v", err)
	}
	ivCopy := make([]byte, lsaTDESIVLen)
	copy(ivCopy, iv[:lsaTDESIVLen])
	out := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, ivCopy)
	mode.CryptBlocks(out, plaintext)
	return out
}

func makeAESKey() []byte {
	k := make([]byte, lsaAESKeyLen)
	for i := range k {
		k[i] = byte(0x40 + i)
	}
	return k
}

func makeTDESKey() []byte {
	k := make([]byte, lsaTDESKeyLen)
	for i := range k {
		k[i] = byte(0x10 + i)
	}
	return k
}

func makeIV16() []byte {
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(0xA0 + i)
	}
	return iv
}

func TestDecryptLsaProtectedMemory_AESCFB_RoundTrip(t *testing.T) {
	// 126 bytes = the fixed PRIMARY_CREDENTIAL_10_NEW size, which is what
	// real Win10/11 ciphertext typically arrives at — and 126 % 8 = 6, so
	// the AES-CFB selection rule fires.
	plaintext := []byte(strings.Repeat("Mimi", 31) + "XX") // 126 bytes
	if len(plaintext) != 126 {
		t.Fatalf("test setup wrong: plaintext len=%d, want 126", len(plaintext))
	}
	if len(plaintext)%lsaTDESBlockSz == 0 {
		t.Fatalf("test setup wrong: 126 should NOT be 8-aligned")
	}
	key := makeAESKey()
	iv := makeIV16()
	ciphertext := encryptAES_CFB(t, plaintext, key, iv)

	got, alg, err := decryptLsaProtectedMemory(ciphertext, key, makeTDESKey(), iv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alg != LsaAlgAES256CFB {
		t.Errorf("alg = %q, want %q", alg, LsaAlgAES256CFB)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch — round-trip failed")
	}
}

func TestDecryptLsaProtectedMemory_3DESCBC_RoundTrip(t *testing.T) {
	// 8-aligned plaintext triggers the 3DES-CBC path.
	plaintext := []byte(strings.Repeat("ABCDEFGH", 11)) // 88 bytes, %8 = 0
	if len(plaintext)%lsaTDESBlockSz != 0 {
		t.Fatalf("test setup wrong: plaintext should be 8-aligned, got len=%d", len(plaintext))
	}
	desKey := makeTDESKey()
	iv := makeIV16()
	ciphertext := encryptTDES_CBC(t, plaintext, desKey, iv)

	got, alg, err := decryptLsaProtectedMemory(ciphertext, makeAESKey(), desKey, iv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alg != LsaAlg3DESCBC {
		t.Errorf("alg = %q, want %q", alg, LsaAlg3DESCBC)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch — round-trip failed")
	}
}

func TestDecryptLsaProtectedMemory_3DESUsesFirst8BytesOfIV(t *testing.T) {
	// Validate the IV[:8] convention by encrypting with crypto/des directly
	// against the first 8 bytes and confirming decryptLsaProtectedMemory (which
	// receives a full 16-byte IV) recovers the same plaintext.
	plaintext := []byte("ABCDEFGHIJKLMNOP") // 16 bytes (% 8 == 0)
	desKey := makeTDESKey()
	fullIV := makeIV16()

	block, _ := des.NewTripleDESCipher(desKey)
	mode := cipher.NewCBCEncrypter(block, fullIV[:lsaTDESIVLen])
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	got, alg, err := decryptLsaProtectedMemory(ciphertext, makeAESKey(), desKey, fullIV)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if alg != LsaAlg3DESCBC {
		t.Errorf("alg = %q, want %q", alg, LsaAlg3DESCBC)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch — IV[:8] convention broken")
	}
}

func TestDecryptLsaProtectedMemory_EmptyCiphertext(t *testing.T) {
	_, _, err := decryptLsaProtectedMemory(nil, makeAESKey(), makeTDESKey(), makeIV16())
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty-ciphertext error, got %v", err)
	}
}

func TestDecryptLsaProtectedMemory_InvalidAESKeyLength(t *testing.T) {
	// Length 9 selects AES, but a 31-byte key fails AES-256 validation.
	ciphertext := bytes.Repeat([]byte{0xCC}, 9)
	_, alg, err := decryptLsaProtectedMemory(ciphertext, make([]byte, 31), makeTDESKey(), makeIV16())
	if alg != LsaAlgAES256CFB {
		t.Errorf("alg = %q, want %q", alg, LsaAlgAES256CFB)
	}
	if err == nil || !strings.Contains(err.Error(), "invalid AES key length") {
		t.Errorf("expected invalid-key-length error, got %v", err)
	}
}

func TestDecryptLsaProtectedMemory_InvalidTDESKeyLength(t *testing.T) {
	// 8-aligned ciphertext selects 3DES; a 23-byte key fails 3DES validation.
	ciphertext := bytes.Repeat([]byte{0xDD}, 16)
	_, alg, err := decryptLsaProtectedMemory(ciphertext, makeAESKey(), make([]byte, 23), makeIV16())
	if alg != LsaAlg3DESCBC {
		t.Errorf("alg = %q, want %q", alg, LsaAlg3DESCBC)
	}
	if err == nil || !strings.Contains(err.Error(), "invalid 3DES key length") {
		t.Errorf("expected invalid-key-length error, got %v", err)
	}
}

func TestDecryptLsaProtectedMemory_ShortIVForAES(t *testing.T) {
	ciphertext := bytes.Repeat([]byte{0xEE}, 9) // % 8 == 1 → AES path
	_, alg, err := decryptLsaProtectedMemory(ciphertext, makeAESKey(), makeTDESKey(), make([]byte, 8))
	if alg != LsaAlgAES256CFB {
		t.Errorf("alg = %q, want %q", alg, LsaAlgAES256CFB)
	}
	if err == nil || !strings.Contains(err.Error(), "invalid IV length") {
		t.Errorf("expected invalid-IV error, got %v", err)
	}
}

func TestDecryptLsaProtectedMemory_ShortIVForTDES(t *testing.T) {
	ciphertext := bytes.Repeat([]byte{0xFF}, 16) // 8-aligned → 3DES path
	_, alg, err := decryptLsaProtectedMemory(ciphertext, makeAESKey(), makeTDESKey(), make([]byte, 4))
	if alg != LsaAlg3DESCBC {
		t.Errorf("alg = %q, want %q", alg, LsaAlg3DESCBC)
	}
	if err == nil || !strings.Contains(err.Error(), "invalid IV length") {
		t.Errorf("expected invalid-IV error, got %v", err)
	}
}

func TestDecryptLsaProtectedMemory_AESPathSelectionMatrix(t *testing.T) {
	// Spot-check that the % 8 selection rule fires correctly for a range of
	// ciphertext sizes (both block-aligned and not). We don't validate the
	// recovered plaintext here — just that the alg label matches mimikatz's
	// `if (cbMemory % 8)` rule.
	cases := []struct {
		size    int
		wantAlg LsaDecryptAlg
	}{
		{1, LsaAlgAES256CFB},   // 1 % 8 = 1
		{7, LsaAlgAES256CFB},   // 7 % 8 = 7
		{8, LsaAlg3DESCBC},     // aligned
		{9, LsaAlgAES256CFB},   // 9 % 8 = 1
		{16, LsaAlg3DESCBC},    // aligned
		{17, LsaAlgAES256CFB},  // 17 % 8 = 1
		{120, LsaAlg3DESCBC},   // aligned
		{126, LsaAlgAES256CFB}, // PRIMARY_CREDENTIAL_10_NEW
	}
	for _, tc := range cases {
		ciphertext := bytes.Repeat([]byte{0x00}, tc.size)
		// Real plaintext content doesn't matter; we want the alg label.
		_, alg, _ := decryptLsaProtectedMemory(ciphertext, makeAESKey(), makeTDESKey(), makeIV16())
		if alg != tc.wantAlg {
			t.Errorf("size=%d: alg = %q, want %q", tc.size, alg, tc.wantAlg)
		}
	}
}
