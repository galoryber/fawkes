package commands

import (
	"testing"
)

// TestSniffExtractLDAPExtraErrors covers intermediate error branches not hit by the main test.
// Each case gets past one more check than the previous before returning nil.
func TestSniffExtractLDAPExtraErrors(t *testing.T) {
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 389}

	t.Run("malformed outer SEQUENCE length (indefinite form)", func(t *testing.T) {
		// 0x30 tag + 0x80 (indefinite length) → derSkipTL returns false
		payload := make([]byte, 16)
		payload[0] = 0x30
		payload[1] = 0x80 // indefinite form → fails
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil for malformed outer SEQUENCE length")
		}
	})

	t.Run("messageID not INTEGER tag", func(t *testing.T) {
		// Outer SEQUENCE is valid, but messageID uses OCTET STRING (0x04) instead of INTEGER (0x02)
		invalidMsgID := asn1Wrap(0x04, []byte("notanint"))
		bindReq := asn1Wrap(0x60, append(asn1Integer(3), asn1Wrap(0x04, []byte("u"))...))
		payload := asn1Wrap(0x30, append(invalidMsgID, bindReq...))
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil when messageID tag is not 0x02")
		}
	})

	t.Run("malformed messageID TLV (content overruns)", func(t *testing.T) {
		// messageID tag 0x02 is present but claims 16 content bytes; body has only 10
		seqBody := []byte{0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		payload := asn1Wrap(0x30, seqBody)
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil for malformed messageID TLV")
		}
	})

	t.Run("malformed BindRequest length (indefinite form)", func(t *testing.T) {
		// Valid messageID, BindRequest tag 0x60 present but uses indefinite length
		msgID := asn1Integer(1)                              // {0x02, 0x01, 0x01}
		badBind := append([]byte{0x60, 0x80}, make([]byte, 7)...) // 0x80 = indefinite
		payload := asn1Wrap(0x30, append(msgID, badBind...))
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil for malformed BindRequest length")
		}
	})

	t.Run("version field not INTEGER", func(t *testing.T) {
		// Valid through BindRequest TL, but version uses OCTET STRING instead of INTEGER
		badVersion := asn1Wrap(0x04, []byte{0x03}) // OCTET STRING, not INTEGER
		name := asn1Wrap(0x04, []byte("admin"))
		auth := asn1Wrap(0x80, []byte("pass"))
		bindBody := append(append(badVersion, name...), auth...)
		payload := asn1Wrap(0x30, append(asn1Integer(1), asn1Wrap(0x60, bindBody)...))
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil when version tag is not 0x02")
		}
	})

	t.Run("malformed version TLV (content overruns)", func(t *testing.T) {
		// version tag 0x02 present but claims 10 bytes; only 5 bytes in bindBody
		badVersion := []byte{0x02, 0x0A, 0x03, 0x00, 0x00} // 5 bytes, claims 10
		bindReq := asn1Wrap(0x60, badVersion)
		payload := asn1Wrap(0x30, append(asn1Integer(1), bindReq...))
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil for malformed version TLV")
		}
	})

	t.Run("name field not OCTET STRING", func(t *testing.T) {
		// Valid version, but name uses CONTEXT 0 tag (0x80) instead of OCTET STRING (0x04)
		version := asn1Integer(3)
		badName := asn1Wrap(0x80, []byte("admin")) // wrong tag
		auth := asn1Wrap(0x80, []byte("pass"))
		bindBody := append(append(version, badName...), auth...)
		payload := asn1Wrap(0x30, append(asn1Integer(1), asn1Wrap(0x60, bindBody)...))
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil when name tag is not 0x04")
		}
	})

	t.Run("malformed name OCTET STRING (content overruns)", func(t *testing.T) {
		// Name tag 0x04 present but claims 32 bytes; only 2 bytes follow
		version := asn1Integer(3)
		badName := []byte{0x04, 0x20, 'a', 'b'} // claims 32 bytes, only 2 present
		bindBody := append(version, badName...)
		payload := asn1Wrap(0x30, append(asn1Integer(1), asn1Wrap(0x60, bindBody)...))
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil for malformed name OCTET STRING")
		}
	})

	t.Run("SASL authentication (not simple bind)", func(t *testing.T) {
		// Valid through name, but auth uses SASL tag 0xA3 instead of simple 0x80
		version := asn1Integer(3)
		name := asn1Wrap(0x04, []byte("admin"))
		sasl := asn1Wrap(0xA3, []byte("GSSAPI")) // SASL, not simple
		bindBody := append(append(version, name...), sasl...)
		payload := asn1Wrap(0x30, append(asn1Integer(1), asn1Wrap(0x60, bindBody)...))
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil for SASL (non-simple) bind")
		}
	})

	t.Run("malformed password CONTEXT string (content overruns)", func(t *testing.T) {
		// Auth tag 0x80 present but claims 32 bytes; only 3 bytes follow
		version := asn1Integer(3)
		name := asn1Wrap(0x04, []byte("admin"))
		badPwd := []byte{0x80, 0x20, 's', 'e', 'c'} // claims 32 bytes, only 3 present
		bindBody := append(append(version, name...), badPwd...)
		payload := asn1Wrap(0x30, append(asn1Integer(1), asn1Wrap(0x60, bindBody)...))
		if got := sniffExtractLDAP(payload, meta); got != nil {
			t.Error("expected nil for malformed password CONTEXT string")
		}
	})
}
