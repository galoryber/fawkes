package discord

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// ─── Mythic Message Encryption ───────────────────────────────────────────────

// buildMythicMessage encrypts and formats a message in the standard Mythic format:
// base64(UUID + AES-CBC-encrypted-payload).
func (d *DiscordProfile) buildMythicMessage(payload []byte, uuid, encKey string) (string, error) {
	var encrypted []byte
	var err error

	if encKey != "" {
		encrypted, err = encryptMessage(payload, encKey)
		if err != nil {
			return "", fmt.Errorf("encryption failed: %w", err)
		}
	} else {
		encrypted = payload
	}

	messageData := append([]byte(uuid), encrypted...)
	return base64.StdEncoding.EncodeToString(messageData), nil
}

// unwrapResponse decodes and decrypts a Mythic response message.
// The input is the base64-encoded message from the MythicMessageWrapper.message field.
func (d *DiscordProfile) unwrapResponse(message, encKey string) ([]byte, error) {
	if encKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode response: %w", err)
		}
		return decryptResponse(decoded, encKey)
	}

	// No encryption — just base64 decode
	decoded, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	// Skip UUID prefix (36 bytes) if present
	if len(decoded) > 36 {
		return decoded[36:], nil
	}
	return decoded, nil
}

// encryptMessage encrypts data using AES-256-CBC + HMAC-SHA256 (Freyja format).
// Returns: IV (16) + Ciphertext + HMAC (32)
func encryptMessage(msg []byte, encKey string) ([]byte, error) {
	if encKey == "" {
		return msg, nil
	}

	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	padded := pkcs7Pad(msg, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	ivCiphertext := append(iv, encrypted...)

	hmacHash := hmac.New(sha256.New, key)
	hmacHash.Write(ivCiphertext)
	hmacBytes := hmacHash.Sum(nil)

	// Zero the key after use
	zeroBytes(key)

	return append(ivCiphertext, hmacBytes...), nil
}

// decryptResponse decrypts a Mythic response (Freyja format).
// Input format: UUID (36) + IV (16) + Ciphertext + HMAC (32)
func decryptResponse(encryptedData []byte, encKey string) ([]byte, error) {
	if encKey == "" {
		return encryptedData, nil
	}

	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}
	defer zeroBytes(key)

	// UUID (36) + IV (16) + at least 1 block + HMAC (32)
	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	iv := encryptedData[36:52]
	hmacBytes := encryptedData[len(encryptedData)-32:]
	ciphertext := encryptedData[52 : len(encryptedData)-32]

	// Verify HMAC (try full data minus HMAC first, then IV+ciphertext only)
	mac := hmac.New(sha256.New, key)
	mac.Write(encryptedData[:len(encryptedData)-32])
	expectedHmac := mac.Sum(nil)

	if !hmac.Equal(hmacBytes, expectedHmac) {
		mac2 := hmac.New(sha256.New, key)
		mac2.Write(encryptedData[36 : len(encryptedData)-32])
		expectedHmac2 := mac2.Sum(nil)
		if !hmac.Equal(hmacBytes, expectedHmac2) {
			return nil, fmt.Errorf("HMAC verification failed")
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}

// pkcs7Pad adds PKCS#7 padding to data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// ─── Config Vault Cryptography ───────────────────────────────────────────────

// vaultEncrypt encrypts plaintext with AES-256-GCM (nonce prepended).
func vaultEncrypt(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

// vaultDecrypt decrypts AES-256-GCM ciphertext with prepended nonce.
func vaultDecrypt(key, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+1 {
		return nil
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil
	}
	return plaintext
}

// zeroBytes overwrites a byte slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// getString safely extracts a string from a map[string]interface{}.
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
