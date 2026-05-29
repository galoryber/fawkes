package commands

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// buildNewerKeysBlob constructs a synthetic Kerberos-Newer-Keys credential blob
// with the given password and key entries. The blob is self-contained: Password
// LSA_UNICODE_STRING header at +0x30 points to inline data, and key offsets
// point to inline key data after the fixed header.
func buildNewerKeysBlob(blobBase uintptr, password string, keys []kerberosKey) []byte {
	pwdBytes := utf16LEBytes(password)
	buf := make([]byte, kerbNewHeaderSize+len(pwdBytes))

	// Password LSA_UNICODE_STRING at +0x30
	binary.LittleEndian.PutUint16(buf[kerbNewPasswordOff:], uint16(len(pwdBytes)))
	binary.LittleEndian.PutUint16(buf[kerbNewPasswordOff+2:], uint16(len(pwdBytes)+2))
	// Buffer pointer = blobBase + offset_of_inline_data
	pwdDataOff := kerbNewHeaderSize
	binary.LittleEndian.PutUint64(buf[kerbNewPasswordOff+8:], uint64(blobBase)+uint64(pwdDataOff))
	copy(buf[pwdDataOff:], pwdBytes)

	// Key array at +0x80 and inline key data after password
	keyDataStart := len(buf)
	for _, k := range keys {
		buf = append(buf, k.KeyBytes...)
	}

	for i, k := range keys {
		off := kerbNewKeysArrayOff + i*kerbNewKeyDataSize
		if off+kerbNewKeyDataSize > kerbNewHeaderSize {
			break
		}
		binary.LittleEndian.PutUint32(buf[off+kerbKeyDataTypeOff:], uint32(k.EncType))
		binary.LittleEndian.PutUint32(buf[off+kerbKeyDataLenOff:], uint32(len(k.KeyBytes)))
		binary.LittleEndian.PutUint32(buf[off+kerbKeyDataOffsetOff:], uint32(keyDataStart))
		keyDataStart += len(k.KeyBytes)
	}

	return buf
}

func TestParseKerberosNewerKeys_FullBlob(t *testing.T) {
	blobBase := uintptr(0x50000)
	desKey, _ := hex.DecodeString("0102030405060708")
	aes128Key, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	aes256Key, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")

	blob := buildNewerKeysBlob(blobBase, "P@ssw0rd!", []kerberosKey{
		{EncType: kerbEncAES256_CTS_HMAC_SHA1_96, KeyBytes: aes256Key},
		{EncType: kerbEncAES128_CTS_HMAC_SHA1_96, KeyBytes: aes128Key},
		{EncType: kerbEncDES_CBC_MD5, KeyBytes: desKey},
	})

	cred := parseKerberosNewerKeys(blob, blobBase)
	if cred.Format != "Kerberos-Newer-Keys" {
		t.Errorf("Format = %q, want Kerberos-Newer-Keys", cred.Format)
	}
	if cred.Password != "P@ssw0rd!" {
		t.Errorf("Password = %q, want P@ssw0rd!", cred.Password)
	}
	if len(cred.Keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(cred.Keys))
	}

	if cred.Keys[0].EncType != kerbEncAES256_CTS_HMAC_SHA1_96 {
		t.Errorf("key[0] type = %v, want AES256", cred.Keys[0].EncType)
	}
	if hex.EncodeToString(cred.Keys[0].KeyBytes) != hex.EncodeToString(aes256Key) {
		t.Errorf("key[0] mismatch")
	}

	if cred.Keys[1].EncType != kerbEncAES128_CTS_HMAC_SHA1_96 {
		t.Errorf("key[1] type = %v, want AES128", cred.Keys[1].EncType)
	}
	if hex.EncodeToString(cred.Keys[1].KeyBytes) != hex.EncodeToString(aes128Key) {
		t.Errorf("key[1] mismatch")
	}

	if cred.Keys[2].EncType != kerbEncDES_CBC_MD5 {
		t.Errorf("key[2] type = %v, want DES", cred.Keys[2].EncType)
	}
	if len(cred.ParseErrors) > 0 {
		t.Errorf("unexpected parse errors: %v", cred.ParseErrors)
	}
}

func TestParseKerberosNewerKeys_NoKeys(t *testing.T) {
	blobBase := uintptr(0x60000)
	blob := buildNewerKeysBlob(blobBase, "test", nil)

	cred := parseKerberosNewerKeys(blob, blobBase)
	if cred.Password != "test" {
		t.Errorf("Password = %q, want test", cred.Password)
	}
	if len(cred.Keys) != 0 {
		t.Errorf("got %d keys, want 0", len(cred.Keys))
	}
}

func TestParseKerberosNewerKeys_TooShort(t *testing.T) {
	cred := parseKerberosNewerKeys(make([]byte, 10), 0x1000)
	if len(cred.ParseErrors) == 0 {
		t.Error("expected parse error for short blob")
	}
}

func TestParseKerberosNewerKeys_BadKeyOffset(t *testing.T) {
	blobBase := uintptr(0x70000)
	blob := buildNewerKeysBlob(blobBase, "x", nil)
	// Manually set a key with an offset past the blob
	off := kerbNewKeysArrayOff
	binary.LittleEndian.PutUint32(blob[off+kerbKeyDataTypeOff:], uint32(kerbEncAES256_CTS_HMAC_SHA1_96))
	binary.LittleEndian.PutUint32(blob[off+kerbKeyDataLenOff:], 32)
	binary.LittleEndian.PutUint32(blob[off+kerbKeyDataOffsetOff:], 99999)

	cred := parseKerberosNewerKeys(blob, blobBase)
	if len(cred.ParseErrors) == 0 {
		t.Error("expected parse error for out-of-bounds key offset")
	}
	if len(cred.Keys) != 0 {
		t.Errorf("got %d keys, want 0 (invalid offset)", len(cred.Keys))
	}
}

func TestParseKerberosOld_WithPassword(t *testing.T) {
	blobBase := uintptr(0x80000)
	pwdBytes := utf16LEBytes("MyPassword123")
	blob := make([]byte, kerbOldHeaderSize+len(pwdBytes))

	// Password at +0x20
	binary.LittleEndian.PutUint16(blob[0x20:], uint16(len(pwdBytes)))
	binary.LittleEndian.PutUint16(blob[0x22:], uint16(len(pwdBytes)+2))
	binary.LittleEndian.PutUint64(blob[0x28:], uint64(blobBase)+uint64(kerbOldHeaderSize))
	copy(blob[kerbOldHeaderSize:], pwdBytes)

	cred := parseKerberosOld(blob, blobBase)
	if cred.Format != "Kerberos" {
		t.Errorf("Format = %q, want Kerberos", cred.Format)
	}
	if cred.Password != "MyPassword123" {
		t.Errorf("Password = %q, want MyPassword123", cred.Password)
	}
	if len(cred.ParseErrors) > 0 {
		t.Errorf("unexpected errors: %v", cred.ParseErrors)
	}
}

func TestParseKerberosOld_TooShort(t *testing.T) {
	cred := parseKerberosOld(make([]byte, 10), 0x1000)
	if len(cred.ParseErrors) == 0 {
		t.Error("expected parse error for short blob")
	}
}

func TestParseKerberosOld_EmptyPassword(t *testing.T) {
	blob := make([]byte, kerbOldHeaderSize)
	// Password Length = 0 at +0x20
	cred := parseKerberosOld(blob, 0x90000)
	if cred.Password != "" {
		t.Errorf("Password = %q, want empty", cred.Password)
	}
}

func TestExtractInlineUnicodeString_Normal(t *testing.T) {
	blobBase := uintptr(0xA0000)
	strBytes := utf16LEBytes("Hello")
	blob := make([]byte, 16+len(strBytes))
	// LSA_UNICODE_STRING header at offset 0
	binary.LittleEndian.PutUint16(blob[0:], uint16(len(strBytes)))
	binary.LittleEndian.PutUint16(blob[2:], uint16(len(strBytes)+2))
	binary.LittleEndian.PutUint64(blob[8:], uint64(blobBase)+16)
	copy(blob[16:], strBytes)

	s, length := extractInlineUnicodeString(blob, 0, blobBase)
	if s != "Hello" {
		t.Errorf("got %q, want Hello", s)
	}
	if length != uint16(len(strBytes)) {
		t.Errorf("length = %d, want %d", length, len(strBytes))
	}
}

func TestExtractInlineUnicodeString_ZeroBlobBase(t *testing.T) {
	blob := make([]byte, 32)
	binary.LittleEndian.PutUint16(blob[0:], 10)
	binary.LittleEndian.PutUint64(blob[8:], 0xDEAD)

	s, length := extractInlineUnicodeString(blob, 0, 0)
	if s != "" {
		t.Errorf("got %q, want empty (zero blobBase)", s)
	}
	if length != 10 {
		t.Errorf("length = %d, want 10", length)
	}
}

func TestExtractInlineUnicodeString_OutOfBounds(t *testing.T) {
	blob := make([]byte, 32)
	blobBase := uintptr(0xB0000)
	binary.LittleEndian.PutUint16(blob[0:], 100) // length 100 but blob is only 32 bytes
	binary.LittleEndian.PutUint16(blob[2:], 100)
	binary.LittleEndian.PutUint64(blob[8:], uint64(blobBase)+16)

	s, length := extractInlineUnicodeString(blob, 0, blobBase)
	if s != "" {
		t.Errorf("got %q, want empty (out of bounds)", s)
	}
	if length != 100 {
		t.Errorf("length = %d, want 100", length)
	}
}

func TestKerbEncType_String(t *testing.T) {
	cases := map[kerbEncType]string{
		kerbEncDES_CBC_MD5:             "des-cbc-md5",
		kerbEncAES128_CTS_HMAC_SHA1_96: "aes128-cts-hmac-sha1-96",
		kerbEncAES256_CTS_HMAC_SHA1_96: "aes256-cts-hmac-sha1-96",
		kerbEncRC4_HMAC:                "rc4-hmac",
		42:                             "etype-42",
	}
	for et, want := range cases {
		if got := et.String(); got != want {
			t.Errorf("kerbEncType(%d).String() = %q, want %q", et, got, want)
		}
	}
}
