package commands

import (
	"encoding/binary"
	"strings"
	"testing"
)

// --- buildAXFRQuery tests ---

func TestBuildAXFRQuery_StructureAndType(t *testing.T) {
	msg := buildAXFRQuery("example.com")
	// DNS header is 12 bytes; question section follows
	if len(msg) < 12 {
		t.Fatalf("query too short: %d bytes, want at least 12", len(msg))
	}

	// Flags: standard query (0x0000)
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags != 0x0000 {
		t.Errorf("flags = 0x%04x, want 0x0000", flags)
	}

	// QDCOUNT = 1
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdCount)
	}

	// ANCOUNT, NSCOUNT, ARCOUNT = 0
	for i, name := range []string{"ANCOUNT", "NSCOUNT", "ARCOUNT"} {
		val := binary.BigEndian.Uint16(msg[6+i*2 : 8+i*2])
		if val != 0 {
			t.Errorf("%s = %d, want 0", name, val)
		}
	}
}

func TestBuildAXFRQuery_QTypeIsAXFR(t *testing.T) {
	msg := buildAXFRQuery("test.local")
	// Find QTYPE by scanning past the encoded domain name
	offset := 12
	for offset < len(msg) {
		labelLen := int(msg[offset])
		if labelLen == 0 {
			offset++ // skip root null
			break
		}
		offset += 1 + labelLen
	}
	if offset+2 > len(msg) {
		t.Fatalf("message too short to contain QTYPE at offset %d", offset)
	}
	qtype := binary.BigEndian.Uint16(msg[offset : offset+2])
	if qtype != 252 { // AXFR = 252
		t.Errorf("QTYPE = %d, want 252 (AXFR)", qtype)
	}
}

func TestBuildAXFRQuery_DomainEncoding(t *testing.T) {
	msg := buildAXFRQuery("mail.example.com")
	// Header is 12 bytes; domain encoding starts at offset 12
	// Expected: \x04mail\x07example\x03com\x00
	offset := 12
	labels := []string{"mail", "example", "com"}
	for _, label := range labels {
		if offset >= len(msg) {
			t.Fatalf("ran out of message bytes")
		}
		labelLen := int(msg[offset])
		if labelLen != len(label) {
			t.Errorf("label %q: encoded length = %d, want %d", label, labelLen, len(label))
		}
		offset++
		got := string(msg[offset : offset+labelLen])
		if got != label {
			t.Errorf("label = %q, want %q", got, label)
		}
		offset += labelLen
	}
	if msg[offset] != 0 {
		t.Errorf("root label = 0x%02x, want 0x00", msg[offset])
	}
}

// --- decodeDNSName tests ---

func encodeDNSName(domain string) []byte {
	var buf []byte
	for _, label := range strings.Split(domain, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // root
	return buf
}

func TestDecodeDNSName_Simple(t *testing.T) {
	msg := encodeDNSName("www.example.com")
	got := decodeDNSName(msg, 0)
	if got != "www.example.com" {
		t.Errorf("decodeDNSName = %q, want www.example.com", got)
	}
}

func TestDecodeDNSName_Root(t *testing.T) {
	// Just a root label
	msg := []byte{0x00}
	got := decodeDNSName(msg, 0)
	if got != "." {
		t.Errorf("decodeDNSName(root) = %q, want .", got)
	}
}

func TestDecodeDNSName_Empty(t *testing.T) {
	got := decodeDNSName([]byte{}, 0)
	if got != "." {
		t.Errorf("decodeDNSName(empty) = %q, want .", got)
	}
}

func TestDecodeDNSName_CompressionPointer(t *testing.T) {
	// Build a message where the answer section uses a pointer to the question domain.
	// Question: example.com at offset 12
	// Answer name: pointer 0xC0 0x0C (offset 12)
	question := encodeDNSName("example.com")
	header := make([]byte, 12)
	msg := append(header, question...)
	// Answer section starts after header+question; pointer to offset 12
	msg = append(msg, 0xC0, 0x0C)

	pointerOffset := 12 + len(question)
	got := decodeDNSName(msg, pointerOffset)
	if got != "example.com" {
		t.Errorf("decodeDNSName(pointer) = %q, want example.com", got)
	}
}

func TestDecodeDNSName_LoopProtection(t *testing.T) {
	// Create a self-referencing pointer (infinite loop)
	msg := make([]byte, 14)
	msg[0] = 0xC0 // pointer at offset 0 → offset 0 (loop)
	msg[1] = 0x00
	// Should not infinite-loop; visited map breaks the cycle
	got := decodeDNSName(msg, 0)
	// Any non-hanging result is acceptable
	_ = got
}

func TestDecodeDNSName_SingleLabel(t *testing.T) {
	msg := encodeDNSName("localhost")
	got := decodeDNSName(msg, 0)
	if got != "localhost" {
		t.Errorf("decodeDNSName = %q, want localhost", got)
	}
}

// --- skipDNSName tests ---

func TestSkipDNSName_SimpleLabel(t *testing.T) {
	// \x07example\x03com\x00 — 12 bytes total
	msg := encodeDNSName("example.com")
	after := skipDNSName(msg, 0)
	if after != len(msg) {
		t.Errorf("skipDNSName returned %d, want %d (end of name)", after, len(msg))
	}
}

func TestSkipDNSName_CompressionPointer(t *testing.T) {
	// A pointer is exactly 2 bytes
	msg := []byte{0xC0, 0x0C, 0xFF, 0xFF} // pointer + padding
	after := skipDNSName(msg, 0)
	if after != 2 {
		t.Errorf("skipDNSName(pointer) = %d, want 2", after)
	}
}

func TestSkipDNSName_EmptyName(t *testing.T) {
	msg := []byte{0x00} // root label only
	after := skipDNSName(msg, 0)
	if after != 1 {
		t.Errorf("skipDNSName(root) = %d, want 1", after)
	}
}

// --- parseAXFRResponse tests ---

func TestParseAXFRResponse_NonZeroRcode(t *testing.T) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[2:], 0x0003) // rcode = 3 (NXDOMAIN)
	records, rcode, _ := parseAXFRResponse(buf)
	if rcode != 3 {
		t.Errorf("rcode = %d, want 3", rcode)
	}
	if records != nil {
		t.Errorf("records should be nil on error rcode")
	}
}

func TestParseAXFRResponse_SOACountsCorrectly(t *testing.T) {
	// Build a response with 2 SOA records
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[2:], 0x8400)
	binary.BigEndian.PutUint16(buf[6:], 2) // ANCOUNT = 2

	// SOA record minimal (type=6): name, type, class, ttl, rdlen, rdata
	// We'll use a minimal SOA rdata (28 bytes minimum for two names + serial)
	buildSOA := func() []byte {
		var r []byte
		r = append(r, 0x00)                              // name: root
		r = binary.BigEndian.AppendUint16(r, 6)          // TYPE SOA
		r = binary.BigEndian.AppendUint16(r, 1)          // CLASS IN
		r = binary.BigEndian.AppendUint32(r, 3600)       // TTL
		// Minimal SOA rdata: mname=\x00 rname=\x00 serial(4) + refresh/retry/expire/minttl(16)
		rdata := []byte{0x00, 0x00} // mname=root, rname=root
		rdata = binary.BigEndian.AppendUint32(rdata, 2024010101) // serial
		rdata = append(rdata, make([]byte, 16)...)
		r = binary.BigEndian.AppendUint16(r, uint16(len(rdata)))
		r = append(r, rdata...)
		return r
	}

	buf = append(buf, buildSOA()...)
	buf = append(buf, buildSOA()...)

	_, _, soaCount := parseAXFRResponse(buf)
	if soaCount != 2 {
		t.Errorf("soaCount = %d, want 2", soaCount)
	}
}

// --- formatRR tests ---

func TestFormatRR_ARecord(t *testing.T) {
	rdata := []byte{10, 0, 0, 1}
	rtype, data := formatRR(1, rdata, rdata, 0, 300)
	if rtype != "A" {
		t.Errorf("rtype = %q, want A", rtype)
	}
	if !strings.Contains(data, "10.0.0.1") {
		t.Errorf("data = %q, want 10.0.0.1 in it", data)
	}
}

func TestFormatRR_AAAARecord(t *testing.T) {
	// ::1 in 16 bytes
	rdata := make([]byte, 16)
	rdata[15] = 1
	rtype, data := formatRR(28, rdata, rdata, 0, 3600)
	if rtype != "AAAA" {
		t.Errorf("rtype = %q, want AAAA", rtype)
	}
	if !strings.Contains(data, "::1") {
		t.Errorf("data = %q, want ::1", data)
	}
}

func TestFormatRR_TXTRecord(t *testing.T) {
	// TXT: length byte + content
	content := []byte("v=spf1 include:example.com ~all")
	rdata := append([]byte{byte(len(content))}, content...)
	rtype, data := formatRR(16, rdata, rdata, 0, 3600)
	if rtype != "TXT" {
		t.Errorf("rtype = %q, want TXT", rtype)
	}
	if !strings.Contains(data, "v=spf1") {
		t.Errorf("data = %q, want SPF content in it", data)
	}
}

func TestFormatRR_UnknownType(t *testing.T) {
	rdata := []byte{1, 2, 3}
	rtype, data := formatRR(99, rdata, rdata, 0, 60)
	if !strings.HasPrefix(rtype, "TYPE") {
		t.Errorf("rtype = %q, want TYPE prefix for unknown", rtype)
	}
	if !strings.Contains(data, "3 bytes") {
		t.Errorf("data = %q, want byte count for unknown type", data)
	}
}

func TestFormatRR_ARecordWrongLength(t *testing.T) {
	// A record with wrong RDLEN (not 4 bytes)
	rdata := []byte{1, 2, 3}
	rtype, _ := formatRR(1, rdata, rdata, 0, 60)
	// Should fall through to unknown TYPE handler
	if rtype == "A" {
		t.Error("A record with 3-byte rdata should not return A type")
	}
}

func TestFormatRR_MXRecord(t *testing.T) {
	// MX: pref(2) + name
	name := encodeDNSName("mail.example.com")
	rdata := binary.BigEndian.AppendUint16(nil, 10) // pref=10
	rdata = append(rdata, name...)
	// Build full message: pref + name at rdataOffset
	fullMsg := rdata
	rtype, data := formatRR(15, rdata, fullMsg, 0, 3600)
	if rtype != "MX" {
		t.Errorf("rtype = %q, want MX", rtype)
	}
	if !strings.Contains(data, "pref=10") {
		t.Errorf("data = %q, want pref=10 in it", data)
	}
}

func TestFormatRR_TTLInOutput(t *testing.T) {
	rdata := []byte{192, 168, 1, 1}
	_, data := formatRR(1, rdata, rdata, 0, 86400)
	if !strings.Contains(data, "TTL=86400") {
		t.Errorf("data = %q, want TTL=86400 in it", data)
	}
}
