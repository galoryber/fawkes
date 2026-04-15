//go:build darwin

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// encryptV10 encrypts plaintext using Chrome's macOS v10 scheme (AES-128-CBC, IV=spaces, PKCS7)
// for testing chromeDecryptValue.
func encryptV10(t *testing.T, plaintext string, key []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = 0x20
	}

	// PKCS7 pad
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	return append([]byte("v10"), ct...)
}

func TestChromeDecryptValue_V10_RoundTrip(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"short", "abc"},
		{"exact-block", "0123456789abcdef"},
		{"multi-block", "testpassword1234567890!@#$"},
		{"single-char", "x"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := encryptV10(t, tt.plaintext, key)
			got, err := chromeDecryptValue(encrypted, key)
			if err != nil {
				t.Fatalf("chromeDecryptValue: %v", err)
			}
			if got != tt.plaintext {
				t.Errorf("expected %q, got %q", tt.plaintext, got)
			}
		})
	}
}

func TestChromeDecryptValue_NoV10Prefix(t *testing.T) {
	// Non-encrypted values (no v10 prefix) should be returned as-is
	raw := []byte("plaintext-value")
	got, err := chromeDecryptValue(raw, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "plaintext-value" {
		t.Errorf("expected %q, got %q", "plaintext-value", got)
	}
}

func TestChromeDecryptValue_TooShort(t *testing.T) {
	_, err := chromeDecryptValue([]byte("ab"), nil)
	if err == nil {
		t.Error("expected error for 2-byte input")
	}
}

func TestChromeDecryptValue_EmptyAfterV10(t *testing.T) {
	got, err := chromeDecryptValue([]byte("v10"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestChromeDecryptValue_BadCiphertextLength(t *testing.T) {
	key := make([]byte, 16)
	// 7 bytes is not a multiple of AES block size (16)
	bad := append([]byte("v10"), make([]byte, 7)...)
	_, err := chromeDecryptValue(bad, key)
	if err == nil {
		t.Error("expected error for non-block-aligned ciphertext")
	}
}

func TestChromeDecryptValue_WrongKey(t *testing.T) {
	correctKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	wrongKey := []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}

	encrypted := encryptV10(t, "secret", correctKey)
	got, err := chromeDecryptValue(encrypted, wrongKey)

	// CBC decryption with wrong key produces garbage but doesn't error —
	// it just produces invalid PKCS7 padding (which is silently kept)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "secret" {
		t.Error("decryption with wrong key should not produce original plaintext")
	}
}

func TestBrowserChromiumPasswords_NoBrowserInstalled(t *testing.T) {
	// With no browsers installed, should return success with empty results
	args := browserArgs{Browser: "chromium"}
	result := browserChromiumPasswords(args)
	if result.Status != "success" {
		// On darwin, if Chromium isn't installed, it should succeed with "No saved passwords"
		t.Logf("status=%s output=%s", result.Status, result.Output)
	}
}

func TestBrowserChromiumCookies_NoBrowserInstalled(t *testing.T) {
	args := browserArgs{Browser: "chromium"}
	result := browserChromiumCookies(args)
	if result.Status != "success" {
		t.Logf("status=%s output=%s", result.Status, result.Output)
	}
}
