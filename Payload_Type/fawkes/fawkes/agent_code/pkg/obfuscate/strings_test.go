package obfuscate

import (
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := []byte("testkey123")
	tests := []string{
		"VirtualAllocEx",
		"CreateRemoteThread",
		"NtQueryInformationProcess",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"",
		"x",
		"Hello, World! 你好",
	}
	for _, plaintext := range tests {
		encrypted := Encrypt(plaintext, key)
		if plaintext == "" {
			if encrypted != nil {
				t.Errorf("empty string should produce nil, got %v", encrypted)
			}
			continue
		}
		decrypted := Decrypt(encrypted, key)
		if decrypted != plaintext {
			t.Errorf("round-trip failed: want %q, got %q", plaintext, decrypted)
		}
	}
}

func TestEncryptProducesDifferentOutput(t *testing.T) {
	key := []byte("key")
	plain := "VirtualAllocEx"
	encrypted := Encrypt(plain, key)
	if string(encrypted) == plain {
		t.Error("encrypted should differ from plaintext")
	}
}

func TestDecryptBytesRoundTrip(t *testing.T) {
	key := []byte("secret")
	plain := "CreateRemoteThread"
	encrypted := Encrypt(plain, key)
	decrypted := DecryptBytes(encrypted, key)
	if string(decrypted) != plain {
		t.Errorf("DecryptBytes: want %q, got %q", plain, string(decrypted))
	}
}

func TestEmptyKey(t *testing.T) {
	result := Encrypt("test", nil)
	if result != nil {
		t.Error("nil key should return nil")
	}
	result = Encrypt("test", []byte{})
	if result != nil {
		t.Error("empty key should return nil")
	}
	s := Decrypt([]byte{1, 2, 3}, nil)
	if s != "" {
		t.Error("nil key decrypt should return empty")
	}
}

func TestZero(t *testing.T) {
	key := []byte("k")
	plain := "SensitiveData"
	encrypted := Encrypt(plain, key)
	decrypted := Decrypt(encrypted, key)
	if decrypted != plain {
		t.Fatal("decrypt failed")
	}
	Zero(decrypted)
	// After zeroing, the string's bytes should be all zeros.
	// We can't easily check this from Go since string is immutable,
	// but we verify no panic occurs.
}

func TestZeroEmpty(t *testing.T) {
	// Should not panic
	Zero("")
}

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestSConvenience(t *testing.T) {
	key := []byte("mykey")
	plain := "WriteProcessMemory"
	encrypted := Encrypt(plain, key)
	result := S(encrypted, key)
	if result != plain {
		t.Errorf("S(): want %q, got %q", plain, result)
	}
}

func TestDifferentKeysProduceDifferentOutput(t *testing.T) {
	plain := "test"
	enc1 := Encrypt(plain, []byte("key1"))
	enc2 := Encrypt(plain, []byte("key2"))
	if len(enc1) != len(enc2) {
		t.Fatal("lengths should match")
	}
	same := true
	for i := range enc1 {
		if enc1[i] != enc2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different keys should produce different encrypted output")
	}
}

func TestEncryptWithSeed(t *testing.T) {
	plain := "NtCreateThreadEx"
	encrypted, key := EncryptWithSeed(plain, 12345)
	if len(encrypted) != len(plain) {
		t.Errorf("encrypted length %d != plaintext length %d", len(encrypted), len(plain))
	}
	if len(key) != len(plain) {
		t.Errorf("key length %d != plaintext length %d", len(key), len(plain))
	}
	// Decrypt should recover original
	decrypted := Decrypt(encrypted, key)
	if decrypted != plain {
		t.Errorf("seed-based decrypt: want %q, got %q", plain, decrypted)
	}
}

func TestEncryptWithSeedDeterministic(t *testing.T) {
	plain := "Test"
	enc1, key1 := EncryptWithSeed(plain, 42)
	enc2, key2 := EncryptWithSeed(plain, 42)
	if string(enc1) != string(enc2) {
		t.Error("same seed should produce same encrypted output")
	}
	if string(key1) != string(key2) {
		t.Error("same seed should produce same key")
	}
}

func TestEncryptWithDifferentSeeds(t *testing.T) {
	plain := "Test"
	enc1, _ := EncryptWithSeed(plain, 1)
	enc2, _ := EncryptWithSeed(plain, 2)
	if string(enc1) == string(enc2) {
		t.Error("different seeds should produce different output")
	}
}

func TestGenerateKey(t *testing.T) {
	key := generateKey(12345, 16)
	if len(key) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(key))
	}
	// Key should not be all zeros
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("key should not be all zeros")
	}
}

func TestGenerateKeyZeroLength(t *testing.T) {
	key := generateKey(12345, 0)
	if key != nil {
		t.Error("zero length should return nil")
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := []byte("benchmark-key-16")
	plain := "VirtualAllocEx"
	encrypted := Encrypt(plain, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Decrypt(encrypted, key)
	}
}

func BenchmarkEncryptWithSeed(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EncryptWithSeed("VirtualAllocEx", uint32(i))
	}
}
