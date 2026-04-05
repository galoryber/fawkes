package tcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// --- TCP framing: length-prefixed messages ---

// sendTCP sends a length-prefixed message over TCP.
// Format: [4 bytes big-endian length][payload]
func (t *TCPProfile) sendTCP(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)

	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("failed to write length header: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}
	return nil
}

// recvTCP reads a length-prefixed message from TCP.
func (t *TCPProfile) recvTCP(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("failed to read length header: %w", err)
	}

	length := binary.BigEndian.Uint32(header)
	if length > 10*1024*1024 { // 10 MB max message size
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("failed to read message body: %w", err)
	}

	return data, nil
}

// --- Encryption (same as HTTP profile) ---

// encryptMessage encrypts a message using AES-CBC with HMAC (Freyja format).
// Returns an error if encryption fails — never falls back to plaintext to avoid leaking unencrypted data.
func (t *TCPProfile) encryptMessage(msg []byte) ([]byte, error) {
	encKey := t.getEncryptionKey()
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

	// Freyja format: IV + Ciphertext + HMAC
	ivCiphertext := append(iv, encrypted...)
	mac := hmac.New(sha256.New, key)
	mac.Write(ivCiphertext)
	hmacBytes := mac.Sum(nil)

	return append(ivCiphertext, hmacBytes...), nil
}

func (t *TCPProfile) decryptResponse(encryptedData []byte) ([]byte, error) {
	encKey := t.getEncryptionKey()
	if encKey == "" {
		return encryptedData, nil
	}

	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	iv := encryptedData[36:52]
	hmacBytes := encryptedData[len(encryptedData)-32:]
	ciphertext := encryptedData[52 : len(encryptedData)-32]

	// Verify HMAC
	mac := hmac.New(sha256.New, key)
	mac.Write(encryptedData[:len(encryptedData)-32])
	expectedHmac := mac.Sum(nil)

	if !hmac.Equal(hmacBytes, expectedHmac) {
		// Try alternative: HMAC on IV + ciphertext only
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

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

// getString safely gets a string value from a map
func getString(m map[string]interface{}, key string) string {
	if val, exists := m[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}
