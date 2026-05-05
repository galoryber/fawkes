package commands

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestSniffExtractHTTPBasicAuthEdgeCases covers uncovered paths in the HTTP Basic Auth parser.
func TestSniffExtractHTTPBasicAuthEdgeCases(t *testing.T) {
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49100, DstPort: 80}

	t.Run("auth header without trailing CRLF", func(t *testing.T) {
		// Authorization header at end of payload with no \r\n terminator
		creds := base64.StdEncoding.EncodeToString([]byte("alice:password1"))
		payload := "GET /secure HTTP/1.1\r\nAuthorization: Basic " + creds
		// No \r\n after the token — hits the `if end < 0 { end = len(rest) }` branch
		cred := sniffExtractHTTPBasicAuth([]byte(payload), meta)
		if cred == nil {
			t.Fatal("expected credential for auth header without trailing CRLF")
		}
		if cred.Username != "alice" {
			t.Errorf("username = %q, want alice", cred.Username)
		}
	})

	t.Run("raw (unpadded) base64 via RawStdEncoding fallback", func(t *testing.T) {
		// RawStdEncoding has no padding ('=' chars) — falls back from StdEncoding
		creds := base64.RawStdEncoding.EncodeToString([]byte("bob:hunter2"))
		// Verify it has no padding (so StdEncoding fails and RawStdEncoding is tried)
		if strings.Contains(creds, "=") {
			t.Skip("test credential happened to not need padding")
		}
		payload := "POST /api HTTP/1.1\r\nAuthorization: Basic " + creds + "\r\n\r\n"
		cred := sniffExtractHTTPBasicAuth([]byte(payload), meta)
		if cred == nil {
			t.Fatal("expected credential from raw base64 fallback")
		}
		if cred.Username != "bob" {
			t.Errorf("username = %q, want bob", cred.Username)
		}
	})

	t.Run("invalid base64 returns nil", func(t *testing.T) {
		payload := "GET /secret HTTP/1.1\r\nAuthorization: Basic !!!invalid_base64!!!\r\n\r\n"
		cred := sniffExtractHTTPBasicAuth([]byte(payload), meta)
		if cred != nil {
			t.Error("expected nil for invalid base64")
		}
	})

	t.Run("no colon in decoded credentials", func(t *testing.T) {
		// Base64 of "useronly" (no colon) → parts won't have 2 elements
		payload := "GET /x HTTP/1.1\r\nAuthorization: Basic " + base64.StdEncoding.EncodeToString([]byte("useronly")) + "\r\n\r\n"
		cred := sniffExtractHTTPBasicAuth([]byte(payload), meta)
		if cred != nil {
			t.Error("expected nil for decoded credentials without colon separator")
		}
	})
}

// TestSniffFTPTrackerEdgeCases covers the > 512 byte payload path.
func TestSniffFTPTrackerEdgeCases(t *testing.T) {
	ft := &sniffFTPTracker{pending: make(map[string]string)}
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49100, DstPort: 21}

	t.Run("payload too long (> 512 bytes) returns nil", func(t *testing.T) {
		big := strings.Repeat("A", 513)
		cred := ft.process([]byte(big), meta)
		if cred != nil {
			t.Error("expected nil for oversized FTP payload")
		}
	})
}
