package commands

import (
	"strings"
	"testing"
)

// TestEncryptAESGCMBadKey covers the aes.NewCipher error path (line 217-219)
// in encryptAESGCM — triggered by a key that is not 16, 24, or 32 bytes.
func TestEncryptAESGCMBadKey(t *testing.T) {
	_, err := encryptAESGCM([]byte("badkey"), []byte("plaintext"))
	if err == nil {
		t.Error("expected error for bad key length")
	}
	if !strings.Contains(err.Error(), "aes.NewCipher") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestDecryptAESGCMBadKey covers the aes.NewCipher error path (line 239-241)
// in decryptAESGCM — triggered by a key that is not a valid AES key size.
func TestDecryptAESGCMBadKey(t *testing.T) {
	_, err := decryptAESGCM([]byte("badkey"), make([]byte, 20))
	if err == nil {
		t.Error("expected error for bad key length")
	}
	if !strings.Contains(err.Error(), "aes.NewCipher") {
		t.Errorf("unexpected error: %v", err)
	}
}
