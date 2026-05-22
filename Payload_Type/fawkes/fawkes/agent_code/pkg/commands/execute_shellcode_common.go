package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

type executeShellcodeArgs struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	Technique    string `json:"technique"`
	Encoding     string `json:"encoding"`
	Key          string `json:"key"`
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
