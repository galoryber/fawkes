package commands

import (
	"encoding/base64"
	"testing"
)

// TestSMTPDecodePlainEmptyUsername covers the empty-username branch in smtpDecodePlain
// (line 71-73 in sniff_smtp.go). The decoded blob has 3 null-separated parts but
// parts[1] (authcid / username) is empty: "\x00\x00password".
func TestSMTPDecodePlainEmptyUsername(t *testing.T) {
	// \x00 + \x00 + "password" → parts = ["", "", "password"] → username = ""
	encoded := base64.StdEncoding.EncodeToString([]byte("\x00\x00password"))
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 587}

	cred := smtpDecodePlain(encoded, meta)
	if cred != nil {
		t.Errorf("expected nil for empty username, got %+v", cred)
	}
}

// TestSMTPDecodePlainEmptyPassword covers the empty-password branch in smtpDecodePlain.
// Blob: "\x00username\x00" → parts = ["", "username", ""] → password = ""
func TestSMTPDecodePlainEmptyPassword(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("\x00username\x00"))
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 25}

	cred := smtpDecodePlain(encoded, meta)
	if cred != nil {
		t.Errorf("expected nil for empty password, got %+v", cred)
	}
}

// TestSMTPDecodePlainRawFallback covers the RawStdEncoding fallback path (line 55)
// when StdEncoding fails but RawStdEncoding succeeds — i.e., base64 without padding.
func TestSMTPDecodePlainRawFallback(t *testing.T) {
	// base64 without trailing '=' padding: StdEncoding fails, RawStdEncoding succeeds
	// "\x00admin\x00secret" in raw base64 (no padding)
	encoded := base64.RawStdEncoding.EncodeToString([]byte("\x00admin\x00secret"))
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 587}

	cred := smtpDecodePlain(encoded, meta)
	if cred == nil {
		t.Error("expected credential from raw base64, got nil")
	} else if cred.Username != "admin" || cred.Password != "secret" {
		t.Errorf("unexpected credential: user=%q pass=%q", cred.Username, cred.Password)
	}
}

// TestSniffExtractSMTPAuthDirectBlob covers the "continuation blob" path in
// sniffExtractSMTPAuth (line 42-44) — a bare base64 blob on an SMTP port
// that doesn't start with any SMTP command keyword.
func TestSniffExtractSMTPAuthDirectBlob(t *testing.T) {
	// A valid PLAIN blob sent as a continuation (after server's 334 challenge)
	encoded := base64.StdEncoding.EncodeToString([]byte("\x00user@corp.com\x00hunter2"))
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 587}

	cred := sniffExtractSMTPAuth([]byte(encoded), meta)
	if cred == nil {
		t.Error("expected credential from bare PLAIN blob, got nil")
	} else if cred.Username != "user@corp.com" || cred.Password != "hunter2" {
		t.Errorf("unexpected credential: user=%q pass=%q", cred.Username, cred.Password)
	}
}
