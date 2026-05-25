//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestSealUnsealCredentials_RoundTrip(t *testing.T) {
	orig := &StoredCredentials{
		Domain:   "CORP",
		Username: "admin",
		Password: "S3cretP@ss!",
	}

	sealed := sealCredentials(orig)
	if sealed == nil {
		t.Fatal("sealCredentials returned nil")
	}
	if len(sealed.key) != 32 {
		t.Errorf("key length = %d, want 32", len(sealed.key))
	}
	if len(sealed.blob) == 0 {
		t.Error("blob is empty")
	}

	got := unsealCredentials(sealed)
	if got == nil {
		t.Fatal("unsealCredentials returned nil")
	}
	if got.Domain != "CORP" {
		t.Errorf("Domain = %q, want %q", got.Domain, "CORP")
	}
	if got.Username != "admin" {
		t.Errorf("Username = %q, want %q", got.Username, "admin")
	}
	if got.Password != "S3cretP@ss!" {
		t.Errorf("Password = %q, want %q", got.Password, "S3cretP@ss!")
	}
}

func TestSealCredentials_NilInput(t *testing.T) {
	sealed := sealCredentials(nil)
	if sealed != nil {
		t.Error("sealCredentials(nil) should return nil")
	}
}

func TestUnsealCredentials_NilInput(t *testing.T) {
	got := unsealCredentials(nil)
	if got != nil {
		t.Error("unsealCredentials(nil) should return nil")
	}
}

func TestUnsealCredentials_EmptyKey(t *testing.T) {
	sc := &sealedCredentials{key: nil, blob: []byte{1, 2, 3}}
	got := unsealCredentials(sc)
	if got != nil {
		t.Error("unsealCredentials with empty key should return nil")
	}
}

func TestUnsealCredentials_EmptyBlob(t *testing.T) {
	sc := &sealedCredentials{key: make([]byte, 32), blob: nil}
	got := unsealCredentials(sc)
	if got != nil {
		t.Error("unsealCredentials with empty blob should return nil")
	}
}

func TestUnsealCredentials_CorruptBlob(t *testing.T) {
	orig := &StoredCredentials{Domain: "D", Username: "U", Password: "P"}
	sealed := sealCredentials(orig)
	if sealed == nil {
		t.Fatal("sealCredentials returned nil")
	}

	// Corrupt the ciphertext
	sealed.blob[len(sealed.blob)-1] ^= 0xFF
	got := unsealCredentials(sealed)
	if got != nil {
		t.Error("unsealCredentials with corrupt blob should return nil (auth tag mismatch)")
	}
}

func TestSealCredentials_UniqueKeys(t *testing.T) {
	creds := &StoredCredentials{Domain: "D", Username: "U", Password: "P"}
	s1 := sealCredentials(creds)

	creds2 := &StoredCredentials{Domain: "D", Username: "U", Password: "P"}
	s2 := sealCredentials(creds2)

	if s1 == nil || s2 == nil {
		t.Fatal("sealCredentials returned nil")
	}

	keyMatch := true
	for i := range s1.key {
		if s1.key[i] != s2.key[i] {
			keyMatch = false
			break
		}
	}
	if keyMatch {
		t.Error("two seals should produce different keys")
	}
}

func TestZeroSealedCredentials(t *testing.T) {
	creds := &StoredCredentials{Domain: "D", Username: "U", Password: "P"}
	sealed := sealCredentials(creds)
	if sealed == nil {
		t.Fatal("sealCredentials returned nil")
	}

	zeroSealedCredentials(sealed)

	allZero := true
	for _, b := range sealed.key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("key should be zeroed after zeroSealedCredentials")
	}

	allZero = true
	for _, b := range sealed.blob {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("blob should be zeroed after zeroSealedCredentials")
	}
}

func TestZeroSealedCredentials_Nil(t *testing.T) {
	zeroSealedCredentials(nil)
}

func TestSetGetIdentityCredentials_Encrypted(t *testing.T) {
	tokenMutex.Lock()
	origCreds := gIdentityCreds
	gIdentityCreds = nil
	tokenMutex.Unlock()
	defer func() {
		tokenMutex.Lock()
		gIdentityCreds = origCreds
		tokenMutex.Unlock()
	}()

	SetIdentityCredentials("TESTDOMAIN", "testuser", "encrypted_pass!")

	// Verify internal state is encrypted (not plaintext)
	tokenMutex.Lock()
	if gIdentityCreds == nil {
		tokenMutex.Unlock()
		t.Fatal("gIdentityCreds should not be nil after SetIdentityCredentials")
	}
	if len(gIdentityCreds.key) != 32 {
		t.Errorf("internal key length = %d, want 32", len(gIdentityCreds.key))
	}
	tokenMutex.Unlock()

	// Verify decryption works
	got := GetIdentityCredentials()
	if got == nil {
		t.Fatal("GetIdentityCredentials returned nil")
	}
	if got.Domain != "TESTDOMAIN" {
		t.Errorf("Domain = %q, want %q", got.Domain, "TESTDOMAIN")
	}
	if got.Username != "testuser" {
		t.Errorf("Username = %q, want %q", got.Username, "testuser")
	}
	if got.Password != "encrypted_pass!" {
		t.Errorf("Password = %q, want %q", got.Password, "encrypted_pass!")
	}
}

func TestSetIdentityCredentials_OverwriteZerosOld(t *testing.T) {
	tokenMutex.Lock()
	origCreds := gIdentityCreds
	gIdentityCreds = nil
	tokenMutex.Unlock()
	defer func() {
		tokenMutex.Lock()
		gIdentityCreds = origCreds
		tokenMutex.Unlock()
	}()

	SetIdentityCredentials("D1", "U1", "P1")

	tokenMutex.Lock()
	oldKey := make([]byte, len(gIdentityCreds.key))
	copy(oldKey, gIdentityCreds.key)
	tokenMutex.Unlock()

	SetIdentityCredentials("D2", "U2", "P2")

	got := GetIdentityCredentials()
	if got == nil {
		t.Fatal("GetIdentityCredentials returned nil")
	}
	if got.Password != "P2" {
		t.Errorf("Password = %q, want %q", got.Password, "P2")
	}
}

func TestSealCredentials_PasswordZeroedAfterSeal(t *testing.T) {
	creds := &StoredCredentials{
		Domain:   "D",
		Username: "U",
		Password: "SecretPassword123",
	}

	sealed := sealCredentials(creds)
	if sealed == nil {
		t.Fatal("sealCredentials returned nil")
	}

	if creds.Password != "" {
		t.Errorf("Password should be zeroed after sealCredentials, got %q", creds.Password)
	}
}
