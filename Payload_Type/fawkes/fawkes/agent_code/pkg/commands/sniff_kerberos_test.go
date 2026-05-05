package commands

import (
	"encoding/binary"
	"testing"
)

// TestSniffASN1LenEdgeCases covers boundary cases not hit by existing sniff_test.go tests.
func TestSniffASN1LenEdgeCases(t *testing.T) {
	t.Run("numBytes zero (0x80)", func(t *testing.T) {
		// 0x80 means numBytes=0 → invalid indefinite form, returns -1
		l, n := sniffASN1Len([]byte{0x80})
		if l != -1 || n != 0 {
			t.Errorf("got len=%d bytes=%d; want -1, 0", l, n)
		}
	})

	t.Run("numBytes too large (>4)", func(t *testing.T) {
		// 0x85 = long form with 5 length bytes → unsupported, returns -1
		l, n := sniffASN1Len([]byte{0x85, 0x01, 0x02, 0x03, 0x04, 0x05})
		if l != -1 || n != 0 {
			t.Errorf("got len=%d bytes=%d; want -1, 0", l, n)
		}
	})

	t.Run("numBytes >= len(data) (truncated)", func(t *testing.T) {
		// 0x83 means 3 length bytes, but only 2 follow → truncated
		l, n := sniffASN1Len([]byte{0x83, 0x01, 0x02})
		if l != -1 || n != 0 {
			t.Errorf("got len=%d bytes=%d; want -1, 0", l, n)
		}
	})

	t.Run("long form 3 bytes", func(t *testing.T) {
		// 0x83 with 3 length bytes: 0x00 0x01 0x00 = 256
		l, n := sniffASN1Len([]byte{0x83, 0x00, 0x01, 0x00})
		if l != 256 || n != 4 {
			t.Errorf("got len=%d bytes=%d; want 256, 4", l, n)
		}
	})

	t.Run("long form 4 bytes max", func(t *testing.T) {
		// 0x84 with 4 length bytes: 0x00 0x00 0x01 0x00 = 256
		l, n := sniffASN1Len([]byte{0x84, 0x00, 0x00, 0x01, 0x00})
		if l != 256 || n != 5 {
			t.Errorf("got len=%d bytes=%d; want 256, 5", l, n)
		}
	})
}

// TestSniffASN1SkipEdgeCases covers truncation and invalid-length paths.
func TestSniffASN1SkipEdgeCases(t *testing.T) {
	t.Run("too short (< 2 bytes)", func(t *testing.T) {
		_, ok := sniffASN1Skip([]byte{0x30}, 0x30)
		if ok {
			t.Error("expected failure for 1-byte input")
		}
	})

	t.Run("invalid length (numBytes zero)", func(t *testing.T) {
		// 0x30 0x80 → valid tag but 0x80 is invalid indefinite length
		_, ok := sniffASN1Skip([]byte{0x30, 0x80}, 0x30)
		if ok {
			t.Error("expected failure when sniffASN1Len returns -1")
		}
	})

	t.Run("content extends past end", func(t *testing.T) {
		// tag=0x30, length=10, only 3 bytes of content follow
		_, ok := sniffASN1Skip([]byte{0x30, 0x0A, 0x01, 0x02, 0x03}, 0x30)
		if ok {
			t.Error("expected failure when content overruns buffer")
		}
	})

	t.Run("long form valid", func(t *testing.T) {
		// Build a 130-byte payload with 0x30 0x81 0x82 header
		payload := make([]byte, 133)
		payload[0] = 0x30
		payload[1] = 0x81
		payload[2] = 130 // 130 content bytes
		for i := 3; i < 133; i++ {
			payload[i] = byte(i)
		}
		content, ok := sniffASN1Skip(payload, 0x30)
		if !ok {
			t.Fatal("expected success for valid long-form TLV")
		}
		if len(content) != 130 {
			t.Errorf("content len = %d, want 130", len(content))
		}
	})
}

// TestSniffASN1ContentLenEdgeCases covers the uncovered branches.
func TestSniffASN1ContentLenEdgeCases(t *testing.T) {
	t.Run("data too short (< 2)", func(t *testing.T) {
		cl := sniffASN1ContentLen([]byte{0x30})
		if cl != 0 {
			t.Errorf("got %d, want 0 for 1-byte input", cl)
		}
	})

	t.Run("empty data", func(t *testing.T) {
		cl := sniffASN1ContentLen([]byte{})
		if cl != 0 {
			t.Errorf("got %d, want 0 for empty input", cl)
		}
	})

	t.Run("invalid length byte returns 0", func(t *testing.T) {
		// Second byte is 0x80 (invalid indefinite form) → sniffASN1Len returns -1
		cl := sniffASN1ContentLen([]byte{0x30, 0x80})
		if cl != 0 {
			t.Errorf("got %d, want 0 for invalid length", cl)
		}
	})

	t.Run("normal short form", func(t *testing.T) {
		// 0x30 0x05 ... → content length is 5
		data := []byte{0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
		cl := sniffASN1ContentLen(data)
		if cl != 5 {
			t.Errorf("got %d, want 5", cl)
		}
	})
}

// TestSniffASN1ReadStringEdgeCases covers the uncovered paths.
func TestSniffASN1ReadStringEdgeCases(t *testing.T) {
	t.Run("data too short (< 2)", func(t *testing.T) {
		s, ok := sniffASN1ReadString([]byte{0x1B})
		if ok || s != "" {
			t.Errorf("got ok=%v s=%q; want false, ''", ok, s)
		}
	})

	t.Run("empty data", func(t *testing.T) {
		s, ok := sniffASN1ReadString([]byte{})
		if ok || s != "" {
			t.Errorf("got ok=%v s=%q; want false, ''", ok, s)
		}
	})

	t.Run("content overruns buffer (skip fails)", func(t *testing.T) {
		// Tag=0x1B, length=20, but only 2 bytes follow → sniffASN1Skip fails
		s, ok := sniffASN1ReadString([]byte{0x1B, 0x14, 0x01, 0x02})
		if ok {
			t.Errorf("got ok=true s=%q; want false when skip fails", s)
		}
	})

	t.Run("valid GeneralString", func(t *testing.T) {
		data := asn1String(0x1B, "CONTOSO.COM")
		s, ok := sniffASN1ReadString(data)
		if !ok || s != "CONTOSO.COM" {
			t.Errorf("got ok=%v s=%q; want true, CONTOSO.COM", ok, s)
		}
	})

	t.Run("any tag works (reads current tag)", func(t *testing.T) {
		// sniffASN1ReadString uses data[0] as the expected tag
		data := asn1Wrap(0x04, []byte("hello"))
		s, ok := sniffASN1ReadString(data)
		if !ok || s != "hello" {
			t.Errorf("got ok=%v s=%q; want true, hello", ok, s)
		}
	})
}

// TestSniffExtractKerberosEdgeCases covers additional branches in sniffExtractKerberos.
func TestSniffExtractKerberosEdgeCases(t *testing.T) {
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 88, DstIP: "10.0.0.2", DstPort: 49000}

	t.Run("TCP framing with non-Kerberos inner data", func(t *testing.T) {
		// 4-byte TCP length prefix pointing to HTTP data (not 0x6B/0x6D)
		inner := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")
		framed := make([]byte, 4+len(inner))
		binary.BigEndian.PutUint32(framed[0:4], uint32(len(inner)))
		copy(framed[4:], inner)
		cred := sniffExtractKerberos(framed, meta)
		if cred != nil {
			t.Error("expected nil for TCP framing with non-Kerberos inner payload")
		}
	})

	t.Run("AS-REP with no realm (principal only)", func(t *testing.T) {
		// Build AS-REP without crealm field — should produce username without @realm
		nameStr := asn1String(0x1B, "alice")
		nameSeqOf := asn1Wrap(0x30, nameStr)
		nameTag1 := asn1Wrap(0xA1, nameSeqOf)
		nameType := asn1Wrap(0xA0, asn1Integer(1))
		cname := asn1Wrap(0x30, append(nameType, nameTag1...))

		pvno := asn1Wrap(0xA0, asn1Integer(5))
		msgType := asn1Wrap(0xA1, asn1Integer(11))
		cnameTag := asn1Wrap(0xA4, cname)
		body := append(pvno, msgType...)
		body = append(body, cnameTag...)
		seq := asn1Wrap(0x30, body)
		payload := asn1Wrap(0x6B, seq)

		cred := sniffExtractKerberos(payload, meta)
		if cred == nil {
			t.Fatal("expected credential even without realm")
		}
		if cred.Username != "alice" {
			t.Errorf("username = %q, want alice (no @realm)", cred.Username)
		}
	})

	t.Run("TGS-REP tag 0x6D", func(t *testing.T) {
		// Build a minimal TGS-REP (tag 0x6D instead of 0x6B)
		nameStr := asn1String(0x1B, "bob")
		nameSeqOf := asn1Wrap(0x30, nameStr)
		nameTag1 := asn1Wrap(0xA1, nameSeqOf)
		nameType := asn1Wrap(0xA0, asn1Integer(1))
		cname := asn1Wrap(0x30, append(nameType, nameTag1...))

		pvno := asn1Wrap(0xA0, asn1Integer(5))
		msgType := asn1Wrap(0xA1, asn1Integer(13))
		crealm := asn1Wrap(0xA3, asn1String(0x1B, "CORP.LOCAL"))
		cnameTag := asn1Wrap(0xA4, cname)
		body := append(pvno, msgType...)
		body = append(body, crealm...)
		body = append(body, cnameTag...)
		seq := asn1Wrap(0x30, body)
		payload := asn1Wrap(0x6D, seq) // TGS-REP tag

		cred := sniffExtractKerberos(payload, meta)
		if cred == nil {
			t.Fatal("expected credential from TGS-REP")
		}
		if cred.Protocol != "krb-tgsrep" {
			t.Errorf("protocol = %q, want krb-tgsrep", cred.Protocol)
		}
		if cred.Username != "bob@CORP.LOCAL" {
			t.Errorf("username = %q, want bob@CORP.LOCAL", cred.Username)
		}
	})

	t.Run("outer skip ok but inner not SEQUENCE (0x30)", func(t *testing.T) {
		// AS-REP tag wraps a SET (0x31) instead of SEQUENCE (0x30)
		inner := asn1Wrap(0x31, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
		payload := asn1Wrap(0x6B, inner)
		cred := sniffExtractKerberos(payload, meta)
		if cred != nil {
			t.Error("expected nil when inner tag is not SEQUENCE (0x30)")
		}
	})
}

// TestSniffExtractPrincipalNameEdgeCases covers multi-part names and edge cases.
func TestSniffExtractPrincipalNameEdgeCases(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		name := sniffExtractPrincipalName([]byte{})
		if name != "" {
			t.Errorf("got %q, want empty", name)
		}
	})

	t.Run("wrong outer tag (not 0x30)", func(t *testing.T) {
		data := asn1Wrap(0x31, []byte{0x01, 0x02})
		name := sniffExtractPrincipalName(data)
		if name != "" {
			t.Errorf("got %q, want empty for wrong outer tag", name)
		}
	})

	t.Run("multi-part service name (SPN)", func(t *testing.T) {
		// SPN like cifs/dc01.corp.local → two GeneralStrings in [1] SEQUENCE
		part1 := asn1String(0x1B, "cifs")
		part2 := asn1String(0x1B, "dc01.corp.local")
		nameSeqOf := asn1Wrap(0x30, append(part1, part2...))
		nameTag1 := asn1Wrap(0xA1, nameSeqOf)
		nameType := asn1Wrap(0xA0, asn1Integer(3))
		pname := asn1Wrap(0x30, append(nameType, nameTag1...))

		name := sniffExtractPrincipalName(pname)
		if name != "cifs/dc01.corp.local" {
			t.Errorf("got %q, want cifs/dc01.corp.local", name)
		}
	})

	t.Run("no name-string field [1]", func(t *testing.T) {
		// PrincipalName with only name-type [0], no [1] name-string
		nameType := asn1Wrap(0xA0, asn1Integer(1))
		pname := asn1Wrap(0x30, nameType)
		name := sniffExtractPrincipalName(pname)
		if name != "" {
			t.Errorf("got %q, want empty when no name-string field", name)
		}
	})

	t.Run("truncated inner name-string", func(t *testing.T) {
		// [1] field contains a SEQUENCE with a truncated GeneralString
		truncated := []byte{0x1B, 0x20, 0x01, 0x02} // GeneralString claiming 32 bytes but only 2
		nameSeqOf := asn1Wrap(0x30, truncated)
		nameTag1 := asn1Wrap(0xA1, nameSeqOf)
		nameType := asn1Wrap(0xA0, asn1Integer(1))
		pname := asn1Wrap(0x30, append(nameType, nameTag1...))
		// Should not panic and should return empty (no valid parts)
		name := sniffExtractPrincipalName(pname)
		_ = name // may be empty or partial, just must not panic
	})
}
