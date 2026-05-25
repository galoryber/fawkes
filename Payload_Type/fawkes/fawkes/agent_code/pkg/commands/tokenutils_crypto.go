//go:build windows
// +build windows

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"

	"fawkes/pkg/structs"
)

// sealedCredentials holds AES-256-GCM encrypted credential data.
// Credentials are never stored in plaintext at rest — they are encrypted
// immediately on store and decrypted only when a caller needs them.
type sealedCredentials struct {
	key  []byte // 32-byte AES-256 key (unique per credential set)
	blob []byte // nonce || ciphertext (AES-256-GCM sealed JSON)
}

// sealCredentials encrypts a StoredCredentials into a sealedCredentials.
// The plaintext fields are zeroed after encryption.
func sealCredentials(creds *StoredCredentials) *sealedCredentials {
	if creds == nil {
		return nil
	}

	data, err := json.Marshal(creds)
	if err != nil {
		return nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		structs.ZeroBytes(data)
		return nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		structs.ZeroBytes(data)
		structs.ZeroBytes(key)
		return nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		structs.ZeroBytes(data)
		structs.ZeroBytes(key)
		return nil
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		structs.ZeroBytes(data)
		structs.ZeroBytes(key)
		return nil
	}

	blob := gcm.Seal(nonce, nonce, data, nil)
	structs.ZeroBytes(data)

	structs.ZeroString(&creds.Password)

	return &sealedCredentials{key: key, blob: blob}
}

// unsealCredentials decrypts a sealedCredentials back to StoredCredentials.
func unsealCredentials(sc *sealedCredentials) *StoredCredentials {
	if sc == nil || len(sc.key) == 0 || len(sc.blob) == 0 {
		return nil
	}

	block, err := aes.NewCipher(sc.key)
	if err != nil {
		return nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	nonceSize := gcm.NonceSize()
	if len(sc.blob) < nonceSize+1 {
		return nil
	}

	nonce, ct := sc.blob[:nonceSize], sc.blob[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil
	}

	var creds StoredCredentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		structs.ZeroBytes(plaintext)
		return nil
	}

	structs.ZeroBytes(plaintext)
	return &creds
}

// zeroSealedCredentials overwrites the key and blob of a sealedCredentials.
func zeroSealedCredentials(sc *sealedCredentials) {
	if sc == nil {
		return
	}
	structs.ZeroBytes(sc.key)
	structs.ZeroBytes(sc.blob)
}
