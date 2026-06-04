package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCollectHardwareAttributes_NonEmpty(t *testing.T) {
	attrs := collectHardwareAttributes()
	if len(attrs) == 0 {
		t.Fatal("collectHardwareAttributes returned empty result")
	}
}

func TestCollectHardwareAttributes_Deterministic(t *testing.T) {
	a := collectHardwareAttributes()
	b := collectHardwareAttributes()
	if !bytes.Equal(a, b) {
		t.Errorf("hardware attributes not deterministic: %q vs %q", a, b)
	}
}

func TestGetHardwareFingerprint_Deterministic(t *testing.T) {
	fp1 := getHardwareFingerprint()
	fp2 := getHardwareFingerprint()
	if fp1 != fp2 {
		t.Error("fingerprint should be deterministic across calls")
	}
}

func TestGetHardwareFingerprint_NonZero(t *testing.T) {
	fp := getHardwareFingerprint()
	var zero [32]byte
	if fp == zero {
		t.Error("fingerprint should not be all zeros")
	}
}

func TestGetHardwareFingerprint_Cached(t *testing.T) {
	old := cachedFingerprint
	defer func() { cachedFingerprint = old }()
	cachedFingerprint = nil

	fp1 := getHardwareFingerprint()
	if cachedFingerprint == nil {
		t.Fatal("fingerprint should be cached after first call")
	}
	fp2 := getHardwareFingerprint()
	if fp1 != fp2 {
		t.Error("cached fingerprint should match")
	}
}

func TestDeriveHardwareBoundKey_Length(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	key := deriveHardwareBoundKey(seed)
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}
}

func TestDeriveHardwareBoundKey_Deterministic(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	k1 := deriveHardwareBoundKey(seed)
	k2 := deriveHardwareBoundKey(seed)
	if !bytes.Equal(k1, k2) {
		t.Error("same seed should produce same key on same hardware")
	}
}

func TestDeriveHardwareBoundKey_DifferentSeeds(t *testing.T) {
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)
	rand.Read(s1)
	rand.Read(s2)
	k1 := deriveHardwareBoundKey(s1)
	k2 := deriveHardwareBoundKey(s2)
	if bytes.Equal(k1, k2) {
		t.Error("different seeds should produce different keys")
	}
}

func TestDeriveHardwareBoundKey_NotEqualToSeed(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	seedCopy := make([]byte, 32)
	copy(seedCopy, seed)
	key := deriveHardwareBoundKey(seed)
	if bytes.Equal(key, seedCopy) {
		t.Error("derived key should differ from raw seed")
	}
}

func TestGetCPUBrand_NonEmpty(t *testing.T) {
	brand := getCPUBrand()
	if brand == "" {
		t.Skip("CPU brand unavailable on this platform")
	}
	if len(brand) < 5 {
		t.Errorf("CPU brand suspiciously short: %q", brand)
	}
}

func TestGetCPUBrand_Deterministic(t *testing.T) {
	b1 := getCPUBrand()
	b2 := getCPUBrand()
	if b1 != b2 {
		t.Errorf("CPU brand should be deterministic: %q vs %q", b1, b2)
	}
}

func TestCheckEnvKeyCpuid_MatchesLocalCPU(t *testing.T) {
	brand := getCPUBrand()
	if brand == "" {
		t.Skip("CPU brand unavailable")
	}
	old := envKeyCpuid
	defer func() { envKeyCpuid = old }()

	envKeyCpuid = ".*"
	if !checkEnvironmentKeys() {
		t.Error("wildcard pattern should match any CPU brand")
	}
}

func TestCheckEnvKeyCpuid_RejectsWrongCPU(t *testing.T) {
	old := envKeyCpuid
	defer func() { envKeyCpuid = old }()

	envKeyCpuid = "NONEXISTENT_CPU_MODEL_12345"
	if checkEnvironmentKeys() {
		t.Error("non-matching pattern should reject")
	}
}

func TestCheckEnvKeyCpuid_EmptySkipsCheck(t *testing.T) {
	old := envKeyCpuid
	defer func() { envKeyCpuid = old }()

	envKeyCpuid = ""
	if !checkEnvironmentKeys() {
		t.Error("empty env_key_cpuid should skip the check")
	}
}

func TestDeriveHardwareBoundKey_EncryptDecryptRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	key := deriveHardwareBoundKey(seed)

	plaintext := []byte("sensitive config data for round-trip test")
	ct := sleepEncrypt(key, plaintext)
	if ct == nil {
		t.Fatal("encryption failed")
	}

	result := sleepDecrypt(key, ct)
	if !bytes.Equal(result, plaintext) {
		t.Error("round-trip failed: decrypted data doesn't match original")
	}
}

func TestDeriveHardwareBoundKey_WrongKeyFails(t *testing.T) {
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)
	rand.Read(s1)
	rand.Read(s2)
	k1 := deriveHardwareBoundKey(s1)
	k2 := deriveHardwareBoundKey(s2)

	ct := sleepEncrypt(k1, []byte("secret"))
	result := sleepDecrypt(k2, ct)
	if result != nil {
		t.Error("decryption with wrong key should fail")
	}
}
