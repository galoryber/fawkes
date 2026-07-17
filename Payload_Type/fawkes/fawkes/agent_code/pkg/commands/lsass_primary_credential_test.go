package commands

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// makePrimaryCredential10NewBuf builds a synthetic 126-byte plaintext blob
// matching the Win10 1607+ / Win11 23H2 PRIMARY_CREDENTIAL_10_NEW layout.
// Each hash slot is filled with a distinguishable byte pattern so the parser
// extraction can be verified.
func makePrimaryCredential10NewBuf(isNt, isLm, isSha bool, ntPattern, lmPattern, shaPattern byte) []byte {
	buf := make([]byte, PrimaryCredential10NewLayout.FixedSize)
	if isNt {
		buf[PrimaryCredential10NewLayout.IsNtOff] = 1
	}
	if isLm {
		buf[PrimaryCredential10NewLayout.IsLmOff] = 1
	}
	if isSha {
		buf[PrimaryCredential10NewLayout.IsShaOff] = 1
	}
	for i := 0; i < primaryCredHashLenNT; i++ {
		buf[PrimaryCredential10NewLayout.NtHashOff+i] = ntPattern + byte(i)
	}
	for i := 0; i < primaryCredHashLenLM; i++ {
		buf[PrimaryCredential10NewLayout.LmHashOff+i] = lmPattern + byte(i)
	}
	for i := 0; i < primaryCredHashLenSHA; i++ {
		buf[PrimaryCredential10NewLayout.ShaHashOff+i] = shaPattern + byte(i)
	}
	// Stamp the LSA_UNICODE_STRING headers so the diagnostic-length fields
	// surface non-zero values.
	binary.LittleEndian.PutUint16(buf[PrimaryCredential10NewLayout.LogonDomainOff:PrimaryCredential10NewLayout.LogonDomainOff+2], 8)
	binary.LittleEndian.PutUint16(buf[PrimaryCredential10NewLayout.LogonDomainOff+2:PrimaryCredential10NewLayout.LogonDomainOff+4], 16)
	binary.LittleEndian.PutUint16(buf[PrimaryCredential10NewLayout.UserNameOff:PrimaryCredential10NewLayout.UserNameOff+2], 14)
	binary.LittleEndian.PutUint16(buf[PrimaryCredential10NewLayout.UserNameOff+2:PrimaryCredential10NewLayout.UserNameOff+4], 28)
	return buf
}

func TestParsePrimaryCredential10New_ExtractsHashesAndFlags(t *testing.T) {
	buf := makePrimaryCredential10NewBuf(true, false, true, 0x10, 0x80, 0xAA)

	parsed, err := parsePrimaryCredential10New(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.IsNtOwfPassword {
		t.Errorf("IsNtOwfPassword = false, want true")
	}
	if parsed.IsLmOwfPassword {
		t.Errorf("IsLmOwfPassword = true, want false")
	}
	if !parsed.IsShaOwPassword {
		t.Errorf("IsShaOwPassword = false, want true")
	}
	if parsed.Layout != PrimaryCredential10NewLayout.Name {
		t.Errorf("Layout = %q, want %q", parsed.Layout, PrimaryCredential10NewLayout.Name)
	}
	for i := byte(0); i < primaryCredHashLenNT; i++ {
		if parsed.NtOwfPassword[i] != 0x10+i {
			t.Errorf("NT[%d] = 0x%02X, want 0x%02X", i, parsed.NtOwfPassword[i], 0x10+i)
		}
	}
	for i := byte(0); i < primaryCredHashLenLM; i++ {
		if parsed.LmOwfPassword[i] != 0x80+i {
			t.Errorf("LM[%d] = 0x%02X, want 0x%02X", i, parsed.LmOwfPassword[i], 0x80+i)
		}
	}
	for i := byte(0); i < primaryCredHashLenSHA; i++ {
		if parsed.ShaOwPassword[i] != 0xAA+i {
			t.Errorf("SHA[%d] = 0x%02X, want 0x%02X", i, parsed.ShaOwPassword[i], 0xAA+i)
		}
	}
	if parsed.UserNameHeaderLength != 14 || parsed.UserNameHeaderMaxLen != 28 {
		t.Errorf("UserName header = (%d/%d), want (14/28)", parsed.UserNameHeaderLength, parsed.UserNameHeaderMaxLen)
	}
	if parsed.LogonDomainHeaderLength != 8 || parsed.LogonDomainHeaderMaxLen != 16 {
		t.Errorf("LogonDomain header = (%d/%d), want (8/16)", parsed.LogonDomainHeaderLength, parsed.LogonDomainHeaderMaxLen)
	}
}

func TestParsePrimaryCredential10New_ShortPlaintextRejected(t *testing.T) {
	short := bytes.Repeat([]byte{0xCC}, 64)
	_, err := parsePrimaryCredential10New(short)
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected short-plaintext error, got %v", err)
	}
}

func TestParsePrimaryCredential10New_AllZeroPlaintext(t *testing.T) {
	// All-zero plaintext is what a wrong key produces. Parser shouldn't fail
	// fatally — it should return zero hashes + false flags so the caller can
	// filter on hashes.NtHashHex == "" / IsNt == false.
	buf := make([]byte, PrimaryCredential10NewLayout.FixedSize)
	parsed, err := parsePrimaryCredential10New(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.IsNtOwfPassword || parsed.IsLmOwfPassword || parsed.IsShaOwPassword {
		t.Errorf("flags = (%v/%v/%v), want all false", parsed.IsNtOwfPassword, parsed.IsLmOwfPassword, parsed.IsShaOwPassword)
	}
	if !allZeroBytes(parsed.NtOwfPassword[:]) {
		t.Errorf("NT hash should be all zero")
	}
}

func TestAllZeroBytes(t *testing.T) {
	if !allZeroBytes(nil) {
		t.Errorf("nil should be all-zero")
	}
	if !allZeroBytes([]byte{}) {
		t.Errorf("empty should be all-zero")
	}
	if !allZeroBytes([]byte{0, 0, 0, 0}) {
		t.Errorf("zeros should be all-zero")
	}
	if allZeroBytes([]byte{0, 0, 1, 0}) {
		t.Errorf("non-zero should not be all-zero")
	}
}

func TestHashdumpDumpLine_FormatMatchesSAMOutput(t *testing.T) {
	var nt, lm [16]byte
	for i := range nt {
		nt[i] = byte(0x10 + i)
	}
	// Empty LM, hasLm=false
	line := hashdumpDumpLine("Administrator", nt, lm, false)
	want := "Administrator:0:aad3b435b51404eeaad3b435b51404ee:101112131415161718191a1b1c1d1e1f:::"
	if line != want {
		t.Errorf("dump line = %q, want %q", line, want)
	}

	// With LM hash present
	for i := range lm {
		lm[i] = byte(0x80 + i)
	}
	line = hashdumpDumpLine("Bob", nt, lm, true)
	want = "Bob:0:808182838485868788898a8b8c8d8e8f:101112131415161718191a1b1c1d1e1f:::"
	if line != want {
		t.Errorf("dump line with LM = %q, want %q", line, want)
	}
}

func TestHashdumpDumpLine_EmptyUserNameOrZeroHashOmitted(t *testing.T) {
	var nt, lm [16]byte
	for i := range nt {
		nt[i] = byte(0x10 + i)
	}
	if line := hashdumpDumpLine("", nt, lm, false); line != "" {
		t.Errorf("expected empty line for blank username, got %q", line)
	}
	var zeroNt [16]byte
	if line := hashdumpDumpLine("Bob", zeroNt, lm, false); line != "" {
		t.Errorf("expected empty line for zero NT hash, got %q", line)
	}
}

func TestHashdumpDumpLine_LMFlagButZeroHash_FallsBackToPlaceholder(t *testing.T) {
	var nt, lm [16]byte
	for i := range nt {
		nt[i] = byte(0x55)
	}
	// hasLm=true but lm bytes are all zero — emit the no-LM placeholder.
	line := hashdumpDumpLine("Carol", nt, lm, true)
	if !strings.Contains(line, "aad3b435b51404eeaad3b435b51404ee") {
		t.Errorf("expected no-LM placeholder, got %q", line)
	}
}

func TestParsePrimaryCredential10NewLayoutOffsets(t *testing.T) {
	// Lock the calibrated offsets in a test so accidental changes are caught.
	wantOffsets := map[string]int{
		"FixedSize":      0x7E,
		"LogonDomainOff": 0x00,
		"UserNameOff":    0x10,
		"IsIsoOff":       0x28,
		"IsNtOff":        0x29,
		"IsLmOff":        0x2A,
		"IsShaOff":       0x2B,
		"NtHashOff":      0x4A,
		"LmHashOff":      0x5A,
		"ShaHashOff":     0x6A,
	}
	got := map[string]int{
		"FixedSize":      PrimaryCredential10NewLayout.FixedSize,
		"LogonDomainOff": PrimaryCredential10NewLayout.LogonDomainOff,
		"UserNameOff":    PrimaryCredential10NewLayout.UserNameOff,
		"IsIsoOff":       PrimaryCredential10NewLayout.IsIsoOff,
		"IsNtOff":        PrimaryCredential10NewLayout.IsNtOff,
		"IsLmOff":        PrimaryCredential10NewLayout.IsLmOff,
		"IsShaOff":       PrimaryCredential10NewLayout.IsShaOff,
		"NtHashOff":      PrimaryCredential10NewLayout.NtHashOff,
		"LmHashOff":      PrimaryCredential10NewLayout.LmHashOff,
		"ShaHashOff":     PrimaryCredential10NewLayout.ShaHashOff,
	}
	for k, v := range wantOffsets {
		if got[k] != v {
			t.Errorf("PrimaryCredential10NewLayout.%s = 0x%X, want 0x%X — DO NOT change without re-validating against mimikatz", k, got[k], v)
		}
	}
}

func TestParsePrimaryCredential10_OlderLayout(t *testing.T) {
	buf := make([]byte, PrimaryCredential10Layout.FixedSize)
	buf[PrimaryCredential10Layout.IsNtOff] = 1
	for i := 0; i < 16; i++ {
		buf[PrimaryCredential10Layout.NtHashOff+i] = 0xAA
	}
	binary.LittleEndian.PutUint16(buf[PrimaryCredential10Layout.LogonDomainOff:], 12)
	binary.LittleEndian.PutUint16(buf[PrimaryCredential10Layout.LogonDomainOff+2:], 14)
	binary.LittleEndian.PutUint16(buf[PrimaryCredential10Layout.UserNameOff:], 10)
	binary.LittleEndian.PutUint16(buf[PrimaryCredential10Layout.UserNameOff+2:], 12)

	parsed, err := parsePrimaryCredential10(buf, PrimaryCredential10Layout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Layout != "PrimaryCredential_10" {
		t.Errorf("Layout = %q, want PrimaryCredential_10", parsed.Layout)
	}
	if !parsed.IsNtOwfPassword {
		t.Error("IsNtOwfPassword should be true")
	}
	for i, b := range parsed.NtOwfPassword {
		if b != 0xAA {
			t.Errorf("NtOwfPassword[%d] = 0x%02X, want 0xAA", i, b)
		}
	}
}

func TestParsePrimaryCredential10Old_NoIsoField(t *testing.T) {
	buf := make([]byte, PrimaryCredential10OldLayout.FixedSize)
	buf[PrimaryCredential10OldLayout.IsNtOff] = 1
	for i := 0; i < 16; i++ {
		buf[PrimaryCredential10OldLayout.NtHashOff+i] = 0xBB
	}
	parsed, err := parsePrimaryCredential10(buf, PrimaryCredential10OldLayout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.IsIso {
		t.Error("IsIso should be false for _10_OLD layout (field not present)")
	}
}

func TestDetectLayout_PlausibleHeaders(t *testing.T) {
	buf := make([]byte, PrimaryCredential10NewLayout.FixedSize+100)
	binary.LittleEndian.PutUint16(buf[0x00:], 26) // LogonDomain Length (even)
	binary.LittleEndian.PutUint16(buf[0x02:], 28) // LogonDomain MaxLen
	binary.LittleEndian.PutUint16(buf[0x10:], 20) // UserName Length (even)
	binary.LittleEndian.PutUint16(buf[0x12:], 22) // UserName MaxLen
	buf[0x29] = 1                                  // IsNt = true (valid boolean)

	layout := detectPrimaryCredentialLayout(buf)
	if layout.Name != "PrimaryCredential_10_NEW" {
		t.Errorf("detected %q, want PrimaryCredential_10_NEW", layout.Name)
	}
}

func TestDetectLayout_FallsBackOnGarbage(t *testing.T) {
	buf := make([]byte, 200)
	for i := range buf {
		buf[i] = 0xFF
	}
	layout := detectPrimaryCredentialLayout(buf)
	if layout.Name != "PrimaryCredential_10_NEW" {
		t.Errorf("fallback should be PrimaryCredential_10_NEW, got %q", layout.Name)
	}
}

func TestDetectLayout_ShortBuffer(t *testing.T) {
	buf := make([]byte, 50) // Too short for any layout
	layout := detectPrimaryCredentialLayout(buf)
	if layout.Name != "PrimaryCredential_10_NEW" {
		t.Errorf("fallback should be PrimaryCredential_10_NEW, got %q", layout.Name)
	}
}
