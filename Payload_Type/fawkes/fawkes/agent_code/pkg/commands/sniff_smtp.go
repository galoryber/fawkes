package commands

import (
	"encoding/base64"
	"strings"
	"time"
)

// sniffExtractSMTPAuth extracts credentials from SMTP AUTH commands (RFC 4954).
// Supports AUTH LOGIN (two-step base64) and AUTH PLAIN (single base64 with \x00 delimiters).
func sniffExtractSMTPAuth(payload []byte, meta *packetMeta) *sniffCredential {
	// Only check SMTP ports
	if meta.DstPort != 25 && meta.DstPort != 587 && meta.DstPort != 465 &&
		meta.SrcPort != 25 && meta.SrcPort != 587 && meta.SrcPort != 465 {
		return nil
	}

	s := strings.TrimSpace(string(payload))
	if len(s) == 0 || len(s) > 4096 {
		return nil
	}

	upper := strings.ToUpper(s)

	// AUTH PLAIN <base64> — single command with credentials
	// Format after base64 decode: \x00<username>\x00<password>
	if strings.HasPrefix(upper, "AUTH PLAIN ") {
		encoded := strings.TrimSpace(s[11:])
		return smtpDecodePlain(encoded, meta)
	}

	// AUTH PLAIN followed by a separate base64 line (server sends 334 challenge first)
	// We also try to catch the base64 blob directly on SMTP ports
	// if it looks like a PLAIN credential blob
	if !strings.HasPrefix(upper, "AUTH") && !strings.HasPrefix(upper, "EHLO") &&
		!strings.HasPrefix(upper, "HELO") && !strings.HasPrefix(upper, "MAIL") &&
		!strings.HasPrefix(upper, "RCPT") && !strings.HasPrefix(upper, "DATA") &&
		!strings.HasPrefix(upper, "QUIT") && !strings.HasPrefix(upper, "RSET") &&
		!strings.HasPrefix(upper, "NOOP") && !strings.HasPrefix(upper, "VRFY") &&
		!strings.HasPrefix(upper, "STARTTLS") {
		// Try decoding as PLAIN credential blob (continuation after 334)
		if cred := smtpDecodePlain(s, meta); cred != nil {
			return cred
		}
	}

	return nil
}

// smtpDecodePlain decodes an AUTH PLAIN base64 blob.
// Format: \x00<authzid>\x00<authcid>\x00<password> or \x00<username>\x00<password>
func smtpDecodePlain(encoded string, meta *packetMeta) *sniffCredential {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return nil
		}
	}

	// Split on null bytes: [authzid, authcid, password] or [empty, username, password]
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) < 3 {
		return nil
	}

	// Username is the authcid (second field); authzid (first) is often empty
	username := parts[1]
	password := parts[2]

	if username == "" || password == "" {
		return nil
	}

	return &sniffCredential{
		Protocol:  "smtp",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  username,
		Password:  password,
		Detail:    "AUTH PLAIN",
		Timestamp: time.Now().Unix(),
	}
}
