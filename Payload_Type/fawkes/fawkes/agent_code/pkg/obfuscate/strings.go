// Package obfuscate provides runtime string decryption for sensitive strings.
// Strings are XOR-encrypted with rotating keys at build time and decrypted
// on-demand at runtime. This defeats static analysis and string-based YARA rules.
//
// Usage:
//
//	// Use the codegen tool to produce encrypted blobs, or manually:
//	encrypted := obfuscate.Encrypt("VirtualAllocEx", key)
//	s := obfuscate.Decrypt(encrypted, key)
//	defer obfuscate.Zero(s)
//	// use s...
package obfuscate

import (
	"unsafe"
)

// Encrypt encrypts a plaintext string using XOR with a rotating key.
// Returns the encrypted bytes.
func Encrypt(plaintext string, key []byte) []byte {
	if len(key) == 0 || len(plaintext) == 0 {
		return nil
	}
	data := []byte(plaintext)
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return result
}

// Decrypt decrypts XOR-encrypted bytes with a rotating key, returning a string.
// The returned string should be zeroed with Zero() after use.
func Decrypt(encrypted []byte, key []byte) string {
	if len(key) == 0 || len(encrypted) == 0 {
		return ""
	}
	buf := make([]byte, len(encrypted))
	for i, b := range encrypted {
		buf[i] = b ^ key[i%len(key)]
	}
	return string(buf)
}

// DecryptBytes decrypts XOR-encrypted bytes with a rotating key, returning a byte slice.
// The caller should zero the returned slice when done.
func DecryptBytes(encrypted []byte, key []byte) []byte {
	if len(key) == 0 || len(encrypted) == 0 {
		return nil
	}
	buf := make([]byte, len(encrypted))
	for i, b := range encrypted {
		buf[i] = b ^ key[i%len(key)]
	}
	return buf
}

// Zero overwrites a string's underlying bytes with zeros.
// This prevents sensitive decrypted strings from lingering in memory.
// Only works on heap-allocated strings (not string constants).
func Zero(s string) {
	if len(s) == 0 {
		return
	}
	// Get pointer to string data and zero it
	p := unsafe.StringData(s)
	if p == nil {
		return
	}
	b := unsafe.Slice(p, len(s))
	clear(b)
}

// ZeroBytes overwrites a byte slice with zeros.
func ZeroBytes(b []byte) {
	clear(b)
}

// S is a convenience function that decrypts and returns a string.
// Short name for use in code where obfuscated strings are common.
//
//	name := obfuscate.S(encVirtualAllocEx, key)
//	defer obfuscate.Zero(name)
func S(encrypted []byte, key []byte) string {
	return Decrypt(encrypted, key)
}

// EncryptWithSeed encrypts a string with a random-looking key derived from a seed.
// The seed is used to generate a deterministic key for reproducible builds.
func EncryptWithSeed(plaintext string, seed uint32) (encrypted []byte, key []byte) {
	// LCG-based key generation for deterministic but varied keys
	key = generateKey(seed, len(plaintext))
	encrypted = Encrypt(plaintext, key)
	return
}

// generateKey creates a deterministic pseudo-random key from a seed.
func generateKey(seed uint32, length int) []byte {
	if length <= 0 {
		return nil
	}
	key := make([]byte, length)
	state := seed
	if state == 0 {
		state = 0xDEADBEEF
	}
	for i := range key {
		// Numerical Recipes LCG (fits uint32)
		state = state*1664525 + 1013904223
		key[i] = byte(state >> 16)
	}
	return key
}
