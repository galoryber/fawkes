package commands

import (
	"encoding/binary"
	"testing"
)

func buildPlaintextBlob(blobBase uintptr, username, domain, password string) []byte {
	uBytes := utf16LEBytes(username)
	dBytes := utf16LEBytes(domain)
	pBytes := utf16LEBytes(password)

	blob := make([]byte, plaintextCredHeaderSize+len(uBytes)+len(dBytes)+len(pBytes))
	dataOff := plaintextCredHeaderSize

	// UserName at +0x00
	binary.LittleEndian.PutUint16(blob[0x00:], uint16(len(uBytes)))
	binary.LittleEndian.PutUint16(blob[0x02:], uint16(len(uBytes)+2))
	binary.LittleEndian.PutUint64(blob[0x08:], uint64(blobBase)+uint64(dataOff))
	copy(blob[dataOff:], uBytes)
	dataOff += len(uBytes)

	// Domain at +0x10
	binary.LittleEndian.PutUint16(blob[0x10:], uint16(len(dBytes)))
	binary.LittleEndian.PutUint16(blob[0x12:], uint16(len(dBytes)+2))
	binary.LittleEndian.PutUint64(blob[0x18:], uint64(blobBase)+uint64(dataOff))
	copy(blob[dataOff:], dBytes)
	dataOff += len(dBytes)

	// Password at +0x20
	binary.LittleEndian.PutUint16(blob[0x20:], uint16(len(pBytes)))
	binary.LittleEndian.PutUint16(blob[0x22:], uint16(len(pBytes)+2))
	binary.LittleEndian.PutUint64(blob[0x28:], uint64(blobBase)+uint64(dataOff))
	copy(blob[dataOff:], pBytes)

	return blob
}

func TestParsePlaintextCredential_Full(t *testing.T) {
	blobBase := uintptr(0xC0000)
	blob := buildPlaintextBlob(blobBase, "Administrator", "CONTOSO", "S3cret!")

	cred := parsePlaintextCredential(blob, blobBase)
	if cred.UserName != "Administrator" {
		t.Errorf("UserName = %q, want Administrator", cred.UserName)
	}
	if cred.Domain != "CONTOSO" {
		t.Errorf("Domain = %q, want CONTOSO", cred.Domain)
	}
	if cred.Password != "S3cret!" {
		t.Errorf("Password = %q, want S3cret!", cred.Password)
	}
	if len(cred.ParseErrors) > 0 {
		t.Errorf("unexpected errors: %v", cred.ParseErrors)
	}
}

func TestParsePlaintextCredential_EmptyPassword(t *testing.T) {
	blobBase := uintptr(0xD0000)
	blob := buildPlaintextBlob(blobBase, "user", "DOMAIN", "")

	cred := parsePlaintextCredential(blob, blobBase)
	if cred.UserName != "user" {
		t.Errorf("UserName = %q, want user", cred.UserName)
	}
	if cred.Password != "" {
		t.Errorf("Password = %q, want empty", cred.Password)
	}
}

func TestParsePlaintextCredential_TooShort(t *testing.T) {
	cred := parsePlaintextCredential(make([]byte, 10), 0x1000)
	if len(cred.ParseErrors) == 0 {
		t.Error("expected parse error for short blob")
	}
}

func TestParsePlaintextCredential_ZeroBlobBase(t *testing.T) {
	blob := buildPlaintextBlob(0xE0000, "user", "DOM", "pass")
	cred := parsePlaintextCredential(blob, 0)
	if cred.UserName != "" {
		t.Errorf("expected empty strings with zero blobBase, got UserName=%q", cred.UserName)
	}
}
