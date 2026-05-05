package commands

import (
	"encoding/binary"
	"testing"
)

// TestSniffParseDNSNameEdgeCases covers compression pointers and error paths.
func TestSniffParseDNSNameEdgeCases(t *testing.T) {
	t.Run("compression pointer", func(t *testing.T) {
		// Packet: at offset 0: pointer to offset 5
		// At offset 5: \x07example\x03com\x00
		data := []byte{
			0xC0, 0x05, // compression pointer to offset 5
			0x00, 0x00, 0x00, // padding
			7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			3, 'c', 'o', 'm',
			0, // root
		}
		name, newOffset := sniffParseDNSName(data, 0)
		if name != "example.com" {
			t.Errorf("name = %q, want example.com", name)
		}
		// When jumped, originalOffset is set to offset+2 after the pointer
		if newOffset != 2 {
			t.Errorf("newOffset = %d, want 2 (after pointer)", newOffset)
		}
	})

	t.Run("compression pointer to itself (infinite loop guard)", func(t *testing.T) {
		// Pointer at offset 0 points back to offset 0 → visited map should break cycle
		data := []byte{0xC0, 0x00}
		name, _ := sniffParseDNSName(data, 0)
		// Should return empty string without hanging
		_ = name
	})

	t.Run("truncated compression pointer (only 1 byte at end)", func(t *testing.T) {
		// The compression pointer needs 2 bytes but only 1 is present
		data := []byte{0xC0} // incomplete pointer
		name, _ := sniffParseDNSName(data, 0)
		if name != "" {
			t.Errorf("got %q, want empty for truncated pointer", name)
		}
	})

	t.Run("label extends past end of buffer", func(t *testing.T) {
		// Label length 10 but only 3 bytes remain
		data := []byte{10, 'a', 'b', 'c'} // claims 10-byte label, only 3 bytes
		name, _ := sniffParseDNSName(data, 0)
		if name != "" {
			t.Errorf("got %q, want empty for truncated label", name)
		}
	})

	t.Run("multi-label with root terminator", func(t *testing.T) {
		data := []byte{3, 'w', 'w', 'w', 4, 't', 'e', 's', 't', 2, 'i', 'o', 0}
		name, off := sniffParseDNSName(data, 0)
		if name != "www.test.io" {
			t.Errorf("name = %q, want www.test.io", name)
		}
		if off != len(data) {
			t.Errorf("offset = %d, want %d", off, len(data))
		}
	})

	t.Run("non-zero starting offset", func(t *testing.T) {
		// Skip 5 bytes of header before the name
		prefix := make([]byte, 5)
		suffix := []byte{4, 't', 'e', 's', 't', 0}
		data := append(prefix, suffix...)
		name, off := sniffParseDNSName(data, 5)
		if name != "test" {
			t.Errorf("name = %q, want test", name)
		}
		if off != len(data) {
			t.Errorf("offset = %d, want %d", off, len(data))
		}
	})
}

// TestSniffExtractDNSEdgeCases covers qtype variants and error paths.
func TestSniffExtractDNSEdgeCases(t *testing.T) {
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 49100, DstIP: "8.8.8.8", DstPort: 53}

	qtypeTests := []struct {
		qtype    uint16
		wantType string
	}{
		{2, "NS"},
		{5, "CNAME"},
		{6, "SOA"},
		{15, "MX"},
		{16, "TXT"},
		{33, "SRV"},
		{252, "AXFR"},
		{255, "ANY"},
		{999, "UNKNOWN"},
	}

	for _, tt := range qtypeTests {
		t.Run("qtype "+tt.wantType, func(t *testing.T) {
			pkt := buildDNSQuery(0x0001, "corp.local", tt.qtype)
			cred := sniffExtractDNS(pkt, meta)
			if cred == nil {
				t.Fatalf("expected credential for qtype %d", tt.qtype)
			}
			want := "type=" + tt.wantType
			if cred.Detail != want {
				t.Errorf("detail = %q, want %q", cred.Detail, want)
			}
		})
	}

	t.Run("qdCount zero", func(t *testing.T) {
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[4:6], 0) // QDCount = 0
		cred := sniffExtractDNS(hdr, meta)
		if cred != nil {
			t.Error("expected nil for zero question count")
		}
	})

	t.Run("qdCount too large (>10)", func(t *testing.T) {
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[4:6], 11) // QDCount = 11
		cred := sniffExtractDNS(hdr, meta)
		if cred != nil {
			t.Error("expected nil for excessive question count")
		}
	})

	t.Run("truncated after name (no QTYPE bytes)", func(t *testing.T) {
		// Build a query but strip the QTYPE/QCLASS bytes
		full := buildDNSQuery(0x0001, "example.com", 1)
		truncated := full[:len(full)-4] // remove last 4 bytes (QTYPE + QCLASS)
		cred := sniffExtractDNS(truncated, meta)
		if cred != nil {
			t.Error("expected nil when QTYPE bytes are missing")
		}
	})

	t.Run("empty name (root label at start)", func(t *testing.T) {
		// Header: QDCount=1, QR=0 — then root label 0x00 immediately
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCount = 1
		pkt := append(hdr, 0x00)               // root label → name="" → return nil
		cred := sniffExtractDNS(pkt, meta)
		if cred != nil {
			t.Error("expected nil for empty DNS name")
		}
	})

	t.Run("source port 53 (response check on src)", func(t *testing.T) {
		// Packets FROM port 53 (with QR=0) should still be captured
		srcMeta := &packetMeta{SrcIP: "8.8.8.8", SrcPort: 53, DstIP: "10.0.0.1", DstPort: 49100}
		pkt := buildDNSQuery(0x0001, "reverse.example", 1)
		cred := sniffExtractDNS(pkt, srcMeta)
		if cred == nil {
			t.Error("expected credential for query arriving on src port 53")
		}
	})
}
