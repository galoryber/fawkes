package main

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

// cachedFingerprint stores the hardware fingerprint after first collection.
// Hardware attributes don't change during process lifetime, so reading once
// and caching avoids repeated file I/O and subprocess calls during each
// sleep cycle.
var cachedFingerprint *[32]byte

// getHardwareFingerprint returns a SHA-256 hash of stable hardware attributes
// (CPU model, machine ID, core count). On the same physical machine, this
// always returns the same value. On different hardware (sandbox, analyst VM),
// the value differs — preventing vault key reconstruction.
func getHardwareFingerprint() [32]byte {
	if cachedFingerprint != nil {
		return *cachedFingerprint
	}
	raw := collectHardwareAttributes()
	fp := sha256.Sum256(raw)
	cachedFingerprint = &fp
	return fp
}

// deriveHardwareBoundKey uses HKDF-SHA256 to mix a random seed with the
// hardware fingerprint, producing a 32-byte key. Knowing the seed alone
// is insufficient to derive the key — the hardware fingerprint acts as
// a binding factor that ties the key to the specific machine.
func deriveHardwareBoundKey(seed []byte) []byte {
	fp := getHardwareFingerprint()
	reader := hkdf.New(sha256.New, seed, fp[:], []byte("fawkes-vault"))
	key := make([]byte, 32)
	if _, err := reader.Read(key); err != nil {
		copy(key, seed)
	}
	return key
}
