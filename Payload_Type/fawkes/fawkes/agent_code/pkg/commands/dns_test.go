package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDnsCommand_Name(t *testing.T) {
	cmd := &DnsCommand{}
	if cmd.Name() != "dns" {
		t.Errorf("expected name 'dns', got %q", cmd.Name())
	}
}

func TestDnsCommand_Description(t *testing.T) {
	cmd := &DnsCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(cmd.Description(), "T1018") {
		t.Error("expected MITRE ATT&CK ID in description")
	}
}

func TestDnsCommand_EmptyParams(t *testing.T) {
	cmd := &DnsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestDnsCommand_InvalidJSON(t *testing.T) {
	cmd := &DnsCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestDnsCommand_MissingTarget(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action: "resolve",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %q", result.Status)
	}
}

func TestDnsCommand_MissingAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Target: "example.com",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing action, got %q", result.Status)
	}
}

func TestDnsCommand_InvalidAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action: "invalid",
		Target: "example.com",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "unknown action") {
		t.Errorf("expected unknown action error, got %q", result.Output)
	}
}

func TestDnsCommand_ResolveLocalhost(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action: "resolve",
		Target: "localhost",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success resolving localhost, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "127.0.0.1") && !strings.Contains(result.Output, "::1") {
		t.Errorf("expected loopback address in output, got %q", result.Output)
	}
}

func TestDnsCommand_ReverseLocalhost(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "reverse",
		Target:  "127.0.0.1",
		Timeout: 3,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Reverse lookup of 127.0.0.1 may succeed or fail depending on system config
	// Just verify it doesn't panic
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("expected success or error, got %q", result.Status)
	}
}

func TestDnsCommand_Registration(t *testing.T) {
	Initialize()
	cmd := GetCommand("dns")
	if cmd == nil {
		t.Fatal("dns command not registered")
	}
	if cmd.Name() != "dns" {
		t.Errorf("expected name 'dns', got %q", cmd.Name())
	}
}

// --- DNS wire format function tests ---

func TestBuildAXFRQuery(t *testing.T) {
	query := buildAXFRQuery("example.com")

	// Header is 12 bytes
	if len(query) < 12 {
		t.Fatalf("query too short: %d bytes", len(query))
	}

	// Verify header fields
	flags := binary.BigEndian.Uint16(query[2:4])
	if flags != 0x0000 {
		t.Errorf("expected flags 0x0000, got 0x%04x", flags)
	}
	qdCount := binary.BigEndian.Uint16(query[4:6])
	if qdCount != 1 {
		t.Errorf("expected 1 question, got %d", qdCount)
	}
	anCount := binary.BigEndian.Uint16(query[6:8])
	if anCount != 0 {
		t.Errorf("expected 0 answers, got %d", anCount)
	}

	// Verify domain encoding: \x07example\x03com\x00
	offset := 12
	if query[offset] != 7 {
		t.Errorf("expected label length 7, got %d", query[offset])
	}
	if string(query[offset+1:offset+8]) != "example" {
		t.Errorf("expected 'example', got %q", string(query[offset+1:offset+8]))
	}
	offset += 8
	if query[offset] != 3 {
		t.Errorf("expected label length 3, got %d", query[offset])
	}
	if string(query[offset+1:offset+4]) != "com" {
		t.Errorf("expected 'com', got %q", string(query[offset+1:offset+4]))
	}
	offset += 4
	if query[offset] != 0 {
		t.Error("expected root label (0)")
	}
	offset++

	// Verify QTYPE=252 (AXFR) and QCLASS=1 (IN)
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	if qtype != 252 {
		t.Errorf("expected QTYPE 252 (AXFR), got %d", qtype)
	}
	qclass := binary.BigEndian.Uint16(query[offset+2 : offset+4])
	if qclass != 1 {
		t.Errorf("expected QCLASS 1 (IN), got %d", qclass)
	}
}

func TestBuildAXFRQuerySubdomain(t *testing.T) {
	query := buildAXFRQuery("sub.example.com")
	// Should have 3 labels: sub(3), example(7), com(3)
	offset := 12
	if query[offset] != 3 {
		t.Errorf("expected first label length 3, got %d", query[offset])
	}
	if string(query[offset+1:offset+4]) != "sub" {
		t.Errorf("expected 'sub', got %q", string(query[offset+1:offset+4]))
	}
}

func TestDecodeDNSName(t *testing.T) {
	// Build a simple DNS message with a name: \x07example\x03com\x00
	msg := []byte{
		// 12-byte header (dummy)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Name at offset 12
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}

	name := decodeDNSName(msg, 12)
	if name != "example.com" {
		t.Errorf("expected 'example.com', got %q", name)
	}
}

func TestDecodeDNSNameCompression(t *testing.T) {
	// Name at offset 12: example.com
	// Name at offset 25: sub + pointer to offset 12
	msg := []byte{
		// Header (12 bytes)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// Name at offset 12: example.com
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0, // offset 24
		// Name at offset 25: sub.example.com (using compression pointer)
		3, 's', 'u', 'b',
		0xC0, 12, // pointer to offset 12
	}

	name := decodeDNSName(msg, 25)
	if name != "sub.example.com" {
		t.Errorf("expected 'sub.example.com', got %q", name)
	}
}

func TestDecodeDNSNameRoot(t *testing.T) {
	msg := []byte{0}
	name := decodeDNSName(msg, 0)
	if name != "." {
		t.Errorf("expected '.', got %q", name)
	}
}

func TestDecodeDNSNameEmpty(t *testing.T) {
	name := decodeDNSName([]byte{}, 0)
	if name != "." {
		t.Errorf("expected '.' for empty message, got %q", name)
	}
}

func TestSkipDNSName(t *testing.T) {
	// \x07example\x03com\x00 = 13 bytes
	msg := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	end := skipDNSName(msg, 0)
	if end != 13 {
		t.Errorf("expected offset 13, got %d", end)
	}
}

func TestSkipDNSNameCompression(t *testing.T) {
	// \x03sub\xC0\x0C = 6 bytes (sub + pointer)
	msg := []byte{3, 's', 'u', 'b', 0xC0, 0x0C}
	end := skipDNSName(msg, 0)
	if end != 6 {
		t.Errorf("expected offset 6, got %d", end)
	}
}

func TestFormatRR_A(t *testing.T) {
	rdata := []byte{192, 168, 1, 1}
	typeName, data := formatRR(1, rdata, nil, 0, 300)
	if typeName != "A" {
		t.Errorf("expected 'A', got %q", typeName)
	}
	if !strings.Contains(data, "192.168.1.1") {
		t.Errorf("expected IP in data, got %q", data)
	}
	if !strings.Contains(data, "TTL=300") {
		t.Errorf("expected TTL in data, got %q", data)
	}
}

func TestFormatRR_AAAA(t *testing.T) {
	rdata := make([]byte, 16)
	rdata[15] = 1 // ::1
	typeName, data := formatRR(28, rdata, nil, 0, 600)
	if typeName != "AAAA" {
		t.Errorf("expected 'AAAA', got %q", typeName)
	}
	if !strings.Contains(data, "::1") {
		t.Errorf("expected '::1' in data, got %q", data)
	}
}

func TestFormatRR_TXT(t *testing.T) {
	txt := "v=spf1 include:_spf.google.com ~all"
	rdata := append([]byte{byte(len(txt))}, []byte(txt)...)
	typeName, data := formatRR(16, rdata, nil, 0, 3600)
	if typeName != "TXT" {
		t.Errorf("expected 'TXT', got %q", typeName)
	}
	if !strings.Contains(data, "v=spf1") {
		t.Errorf("expected TXT content, got %q", data)
	}
}

func TestFormatRR_Unknown(t *testing.T) {
	rdata := []byte{1, 2, 3}
	typeName, data := formatRR(999, rdata, nil, 0, 100)
	if typeName != "TYPE999" {
		t.Errorf("expected 'TYPE999', got %q", typeName)
	}
	if !strings.Contains(data, "3 bytes") {
		t.Errorf("expected byte count in data, got %q", data)
	}
}

func TestParseAXFRResponse_TooShort(t *testing.T) {
	records, rcode, soa := parseAXFRResponse([]byte{1, 2, 3})
	if records != nil || rcode != 0 || soa != 0 {
		t.Error("expected nil/0/0 for short message")
	}
}

func TestParseAXFRResponse_ErrorRcode(t *testing.T) {
	// Build a DNS response with RCODE=5 (REFUSED)
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // TXID
	binary.BigEndian.PutUint16(msg[2:4], 0x8005) // QR=1, RCODE=5
	binary.BigEndian.PutUint16(msg[4:6], 0)      // QDCOUNT
	binary.BigEndian.PutUint16(msg[6:8], 0)      // ANCOUNT

	records, rcode, _ := parseAXFRResponse(msg)
	if records != nil {
		t.Error("expected nil records for error response")
	}
	if rcode != 5 {
		t.Errorf("expected rcode 5, got %d", rcode)
	}
}

func TestParseAXFRResponse_ARecord(t *testing.T) {
	// Build a minimal DNS response with 1 A record
	var msg []byte

	// Header (12 bytes)
	msg = binary.BigEndian.AppendUint16(msg, 0x1234) // TXID
	msg = binary.BigEndian.AppendUint16(msg, 0x8000) // QR=1, RCODE=0
	msg = binary.BigEndian.AppendUint16(msg, 0)      // QDCOUNT=0
	msg = binary.BigEndian.AppendUint16(msg, 1)      // ANCOUNT=1
	msg = binary.BigEndian.AppendUint16(msg, 0)      // NSCOUNT=0
	msg = binary.BigEndian.AppendUint16(msg, 0)      // ARCOUNT=0

	// Answer: example.com A 10.0.0.1
	msg = append(msg, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0) // name
	msg = binary.BigEndian.AppendUint16(msg, 1)                                  // TYPE=A
	msg = binary.BigEndian.AppendUint16(msg, 1)                                  // CLASS=IN
	msg = binary.BigEndian.AppendUint32(msg, 300)                                // TTL
	msg = binary.BigEndian.AppendUint16(msg, 4)                                  // RDLENGTH
	msg = append(msg, 10, 0, 0, 1)                                               // RDATA: 10.0.0.1

	records, rcode, soa := parseAXFRResponse(msg)
	if rcode != 0 {
		t.Fatalf("expected rcode 0, got %d", rcode)
	}
	if soa != 0 {
		t.Errorf("expected 0 SOA records, got %d", soa)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].name != "example.com" {
		t.Errorf("expected name 'example.com', got %q", records[0].name)
	}
	if records[0].rtype != "A" {
		t.Errorf("expected type 'A', got %q", records[0].rtype)
	}
	if !strings.Contains(records[0].data, "10.0.0.1") {
		t.Errorf("expected '10.0.0.1' in data, got %q", records[0].data)
	}
}

// --- Additional wire-format tests ---

// Helper to build DNS response messages for testing.
func buildTestDNSResponse(rcode int, questions int, answers []testDNSRR) []byte {
	var msg []byte
	msg = binary.BigEndian.AppendUint16(msg, 0x1234)
	flags := uint16(0x8000) | uint16(rcode)
	msg = binary.BigEndian.AppendUint16(msg, flags)
	msg = binary.BigEndian.AppendUint16(msg, uint16(questions))
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(answers)))
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)

	for i := 0; i < questions; i++ {
		msg = append(msg, 7)
		msg = append(msg, []byte("example")...)
		msg = append(msg, 3)
		msg = append(msg, []byte("com")...)
		msg = append(msg, 0)
		msg = binary.BigEndian.AppendUint16(msg, 252) // AXFR
		msg = binary.BigEndian.AppendUint16(msg, 1)   // IN
	}

	for _, rr := range answers {
		for _, label := range strings.Split(rr.name, ".") {
			if label == "" {
				continue
			}
			msg = append(msg, byte(len(label)))
			msg = append(msg, []byte(label)...)
		}
		msg = append(msg, 0)
		msg = binary.BigEndian.AppendUint16(msg, rr.rtype)
		msg = binary.BigEndian.AppendUint16(msg, 1) // class IN
		msg = binary.BigEndian.AppendUint32(msg, rr.ttl)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rr.rdata)))
		msg = append(msg, rr.rdata...)
	}
	return msg
}

type testDNSRR struct {
	name  string
	rtype uint16
	ttl   uint32
	rdata []byte
}

func TestBuildAXFRQuery_SubDomainLabels(t *testing.T) {
	query := buildAXFRQuery("a.b.c.d.example.com")
	off := 12
	labels := []string{"a", "b", "c", "d", "example", "com"}
	for _, label := range labels {
		if off >= len(query) {
			t.Fatalf("query too short at label %q", label)
		}
		if int(query[off]) != len(label) {
			t.Errorf("label %q: length byte = %d, want %d", label, query[off], len(label))
		}
		off++
		if string(query[off:off+len(label)]) != label {
			t.Errorf("label = %q, want %q", string(query[off:off+len(label)]), label)
		}
		off += len(label)
	}
	if query[off] != 0 {
		t.Error("expected root label")
	}
}

func TestBuildAXFRQuery_TrailingDot(t *testing.T) {
	q1 := buildAXFRQuery("example.com")
	q2 := buildAXFRQuery("example.com.")
	// Both should encode the same (trailing dot produces empty label, skipped)
	if len(q1) != len(q2) {
		t.Errorf("trailing dot changed length: %d vs %d", len(q1), len(q2))
	}
}

func TestBuildAXFRQuery_SingleLabel(t *testing.T) {
	query := buildAXFRQuery("localhost")
	off := 12
	if query[off] != 9 {
		t.Errorf("label length = %d, want 9", query[off])
	}
	if string(query[off+1:off+10]) != "localhost" {
		t.Errorf("label = %q, want %q", string(query[off+1:off+10]), "localhost")
	}
}

func TestDecodeDNSName_CircularPointer(t *testing.T) {
	// Pointer to itself at offset 0
	msg := []byte{0xC0, 0x00}
	name := decodeDNSName(msg, 0)
	// Should not hang; visited map breaks the loop
	if name != "." {
		t.Errorf("circular pointer: got %q, want %q", name, ".")
	}
}

func TestDecodeDNSName_PointerMidName(t *testing.T) {
	// offset 0: \x03com\x00  ("com")
	// offset 5: \x07example\xC0\x00  ("example" + ptr to offset 0)
	msg := []byte{3}
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0) // offset 4

	msg = append(msg, 7) // offset 5
	msg = append(msg, []byte("example")...)
	msg = append(msg, 0xC0, 0x00) // ptr to offset 0

	name := decodeDNSName(msg, 5)
	if name != "example.com" {
		t.Errorf("got %q, want %q", name, "example.com")
	}
}

func TestDecodeDNSName_OutOfBoundsOffset(t *testing.T) {
	msg := []byte{0}
	name := decodeDNSName(msg, 100)
	if name != "." {
		t.Errorf("out-of-bounds: got %q, want %q", name, ".")
	}
}

func TestDecodeDNSName_TruncatedPointer(t *testing.T) {
	msg := []byte{0xC0} // pointer byte without second byte
	name := decodeDNSName(msg, 0)
	// Should not crash
	_ = name
}

func TestDecodeDNSName_ManyLabels(t *testing.T) {
	var msg []byte
	labels := []string{"a", "bb", "ccc", "dddd", "eeeee", "ffffff", "ggggggg"}
	for _, l := range labels {
		msg = append(msg, byte(len(l)))
		msg = append(msg, []byte(l)...)
	}
	msg = append(msg, 0)

	name := decodeDNSName(msg, 0)
	expected := strings.Join(labels, ".")
	if name != expected {
		t.Errorf("got %q, want %q", name, expected)
	}
}

func TestSkipDNSName_RootLabel(t *testing.T) {
	msg := []byte{0}
	if end := skipDNSName(msg, 0); end != 1 {
		t.Errorf("root label: got %d, want 1", end)
	}
}

func TestSkipDNSName_WithOffset(t *testing.T) {
	// 3 bytes padding + name \x04test\x00
	msg := []byte{0xFF, 0xFF, 0xFF, 4}
	msg = append(msg, []byte("test")...)
	msg = append(msg, 0)

	end := skipDNSName(msg, 3)
	expected := 3 + 1 + 4 + 1
	if end != expected {
		t.Errorf("got %d, want %d", end, expected)
	}
}

func TestFormatRR_NS(t *testing.T) {
	rdataOffset := 10
	msg := make([]byte, rdataOffset)
	msg = append(msg, 3)
	msg = append(msg, []byte("ns1")...)
	msg = append(msg, 7)
	msg = append(msg, []byte("example")...)
	msg = append(msg, 3)
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0)

	rdata := msg[rdataOffset:]
	typeName, data := formatRR(2, rdata, msg, rdataOffset, 86400)
	if typeName != "NS" {
		t.Errorf("typeName = %q, want %q", typeName, "NS")
	}
	if !strings.Contains(data, "ns1.example.com") {
		t.Errorf("data %q should contain NS hostname", data)
	}
	if !strings.Contains(data, "TTL=86400") {
		t.Errorf("data %q should contain TTL", data)
	}
}

func TestFormatRR_CNAME(t *testing.T) {
	rdataOffset := 10
	msg := make([]byte, rdataOffset)
	msg = append(msg, 3)
	msg = append(msg, []byte("www")...)
	msg = append(msg, 7)
	msg = append(msg, []byte("example")...)
	msg = append(msg, 3)
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0)

	rdata := msg[rdataOffset:]
	typeName, data := formatRR(5, rdata, msg, rdataOffset, 1800)
	if typeName != "CNAME" {
		t.Errorf("typeName = %q, want %q", typeName, "CNAME")
	}
	if !strings.Contains(data, "www.example.com") {
		t.Errorf("data %q should contain CNAME target", data)
	}
}

func TestFormatRR_MX(t *testing.T) {
	rdataOffset := 20
	msg := make([]byte, rdataOffset)
	msg = binary.BigEndian.AppendUint16(msg, 10) // preference
	msg = append(msg, 4)
	msg = append(msg, []byte("mail")...)
	msg = append(msg, 7)
	msg = append(msg, []byte("example")...)
	msg = append(msg, 3)
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0)

	rdata := msg[rdataOffset:]
	typeName, data := formatRR(15, rdata, msg, rdataOffset, 600)
	if typeName != "MX" {
		t.Errorf("typeName = %q, want %q", typeName, "MX")
	}
	if !strings.Contains(data, "pref=10") {
		t.Errorf("data %q should contain preference", data)
	}
	if !strings.Contains(data, "mail.example.com") {
		t.Errorf("data %q should contain mail host", data)
	}
}

func TestFormatRR_SRV(t *testing.T) {
	rdataOffset := 10
	msg := make([]byte, rdataOffset)
	msg = binary.BigEndian.AppendUint16(msg, 10)  // priority
	msg = binary.BigEndian.AppendUint16(msg, 5)   // weight
	msg = binary.BigEndian.AppendUint16(msg, 389) // port
	msg = append(msg, 4)
	msg = append(msg, []byte("dc01")...)
	msg = append(msg, 7)
	msg = append(msg, []byte("example")...)
	msg = append(msg, 3)
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0)

	rdata := msg[rdataOffset:]
	typeName, data := formatRR(33, rdata, msg, rdataOffset, 600)
	if typeName != "SRV" {
		t.Errorf("typeName = %q, want %q", typeName, "SRV")
	}
	if !strings.Contains(data, "dc01.example.com") {
		t.Errorf("data %q should contain target", data)
	}
	if !strings.Contains(data, ":389") {
		t.Errorf("data %q should contain port", data)
	}
	if !strings.Contains(data, "priority=10") {
		t.Errorf("data %q should contain priority", data)
	}
	if !strings.Contains(data, "weight=5") {
		t.Errorf("data %q should contain weight", data)
	}
}

func TestFormatRR_SOA(t *testing.T) {
	rdataOffset := 10
	msg := make([]byte, rdataOffset)

	// MNAME
	msg = append(msg, 3)
	msg = append(msg, []byte("ns1")...)
	msg = append(msg, 7)
	msg = append(msg, []byte("example")...)
	msg = append(msg, 3)
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0)
	// RNAME
	msg = append(msg, 5)
	msg = append(msg, []byte("admin")...)
	msg = append(msg, 7)
	msg = append(msg, []byte("example")...)
	msg = append(msg, 3)
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0)
	// Serial + refresh + retry + expire + minimum
	msg = binary.BigEndian.AppendUint32(msg, 2024030101)
	msg = binary.BigEndian.AppendUint32(msg, 3600)
	msg = binary.BigEndian.AppendUint32(msg, 900)
	msg = binary.BigEndian.AppendUint32(msg, 604800)
	msg = binary.BigEndian.AppendUint32(msg, 86400)

	rdata := msg[rdataOffset:]
	typeName, data := formatRR(6, rdata, msg, rdataOffset, 86400)
	if typeName != "SOA" {
		t.Errorf("typeName = %q, want %q", typeName, "SOA")
	}
	if !strings.Contains(data, "ns1.example.com") {
		t.Errorf("data %q should contain MNAME", data)
	}
	if !strings.Contains(data, "admin.example.com") {
		t.Errorf("data %q should contain RNAME", data)
	}
	if !strings.Contains(data, "serial=2024030101") {
		t.Errorf("data %q should contain serial", data)
	}
}

func TestFormatRR_A_WrongLength(t *testing.T) {
	rdata := []byte{1, 2, 3} // 3 bytes, not 4
	typeName, _ := formatRR(1, rdata, nil, 0, 300)
	if typeName != "TYPE1" {
		t.Errorf("malformed A: typeName = %q, want %q", typeName, "TYPE1")
	}
}

func TestFormatRR_AAAA_WrongLength(t *testing.T) {
	rdata := []byte{1, 2, 3, 4, 5, 6, 7, 8} // 8 bytes, not 16
	typeName, _ := formatRR(28, rdata, nil, 0, 300)
	if typeName != "TYPE28" {
		t.Errorf("malformed AAAA: typeName = %q, want %q", typeName, "TYPE28")
	}
}

func TestFormatRR_MX_TooShort(t *testing.T) {
	rdata := []byte{0x00}
	typeName, _ := formatRR(15, rdata, nil, 0, 300)
	if typeName != "TYPE15" {
		t.Errorf("malformed MX: typeName = %q, want %q", typeName, "TYPE15")
	}
}

func TestFormatRR_SRV_TooShort(t *testing.T) {
	rdata := []byte{0x00, 0x01, 0x00, 0x02} // < 6 bytes
	typeName, _ := formatRR(33, rdata, nil, 0, 300)
	if typeName != "TYPE33" {
		t.Errorf("malformed SRV: typeName = %q, want %q", typeName, "TYPE33")
	}
}

func TestFormatRR_TXT_Empty(t *testing.T) {
	rdata := []byte{}
	typeName, _ := formatRR(16, rdata, nil, 0, 300)
	if typeName != "TYPE16" {
		t.Errorf("empty TXT: typeName = %q, want %q", typeName, "TYPE16")
	}
}

func TestFormatRR_A_CommonIPs(t *testing.T) {
	tests := []struct {
		name string
		ip   [4]byte
		want string
	}{
		{"loopback", [4]byte{127, 0, 0, 1}, "127.0.0.1"},
		{"private_10", [4]byte{10, 0, 0, 1}, "10.0.0.1"},
		{"private_172", [4]byte{172, 16, 0, 1}, "172.16.0.1"},
		{"zeros", [4]byte{0, 0, 0, 0}, "0.0.0.0"},
		{"broadcast", [4]byte{255, 255, 255, 255}, "255.255.255.255"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			typeName, data := formatRR(1, tc.ip[:], nil, 0, 60)
			if typeName != "A" {
				t.Errorf("typeName = %q, want %q", typeName, "A")
			}
			if !strings.Contains(data, tc.want) {
				t.Errorf("data %q should contain %q", data, tc.want)
			}
		})
	}
}

func TestFormatRR_AAAA_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	typeName, data := formatRR(28, ip.To16(), nil, 0, 3600)
	if typeName != "AAAA" {
		t.Errorf("typeName = %q, want %q", typeName, "AAAA")
	}
	if !strings.Contains(data, "2001:db8::1") {
		t.Errorf("data %q should contain IPv6", data)
	}
}

func TestParseAXFRResponse_SOACount(t *testing.T) {
	// Build SOA rdata
	var soaRdata []byte
	soaRdata = append(soaRdata, 2)
	soaRdata = append(soaRdata, []byte("ns")...)
	soaRdata = append(soaRdata, 7)
	soaRdata = append(soaRdata, []byte("example")...)
	soaRdata = append(soaRdata, 3)
	soaRdata = append(soaRdata, []byte("com")...)
	soaRdata = append(soaRdata, 0)
	soaRdata = append(soaRdata, 5)
	soaRdata = append(soaRdata, []byte("admin")...)
	soaRdata = append(soaRdata, 7)
	soaRdata = append(soaRdata, []byte("example")...)
	soaRdata = append(soaRdata, 3)
	soaRdata = append(soaRdata, []byte("com")...)
	soaRdata = append(soaRdata, 0)
	soaRdata = binary.BigEndian.AppendUint32(soaRdata, 2024030101)
	soaRdata = binary.BigEndian.AppendUint32(soaRdata, 3600)
	soaRdata = binary.BigEndian.AppendUint32(soaRdata, 900)
	soaRdata = binary.BigEndian.AppendUint32(soaRdata, 604800)
	soaRdata = binary.BigEndian.AppendUint32(soaRdata, 86400)

	answers := []testDNSRR{
		{name: "example.com", rtype: 6, ttl: 86400, rdata: soaRdata},
		{name: "host.example.com", rtype: 1, ttl: 300, rdata: []byte{10, 0, 0, 1}},
	}
	msg := buildTestDNSResponse(0, 0, answers)

	records, rcode, soaCount := parseAXFRResponse(msg)
	if rcode != 0 {
		t.Fatalf("rcode = %d, want 0", rcode)
	}
	if soaCount != 1 {
		t.Errorf("soaCount = %d, want 1", soaCount)
	}
	if len(records) != 2 {
		t.Errorf("got %d records, want 2", len(records))
	}
	if records[0].rtype != "SOA" {
		t.Errorf("first record type = %q, want %q", records[0].rtype, "SOA")
	}
}

func TestParseAXFRResponse_MultipleRecordTypes(t *testing.T) {
	txtData := []byte{11}
	txtData = append(txtData, []byte("hello world")...)

	answers := []testDNSRR{
		{name: "example.com", rtype: 1, ttl: 300, rdata: []byte{1, 2, 3, 4}},
		{name: "example.com", rtype: 28, ttl: 300, rdata: net.ParseIP("::1").To16()},
		{name: "example.com", rtype: 16, ttl: 300, rdata: txtData},
	}
	msg := buildTestDNSResponse(0, 0, answers)

	records, rcode, _ := parseAXFRResponse(msg)
	if rcode != 0 {
		t.Fatalf("rcode = %d, want 0", rcode)
	}
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
	expectedTypes := []string{"A", "AAAA", "TXT"}
	for i, rec := range records {
		if rec.rtype != expectedTypes[i] {
			t.Errorf("record %d: type = %q, want %q", i, rec.rtype, expectedTypes[i])
		}
	}
}

func TestParseAXFRResponse_AllErrorRcodes(t *testing.T) {
	for _, rc := range []int{1, 2, 3, 4, 5, 9} {
		t.Run(fmt.Sprintf("RCODE_%d", rc), func(t *testing.T) {
			msg := buildTestDNSResponse(rc, 0, nil)
			records, rcode, _ := parseAXFRResponse(msg)
			if rcode != rc {
				t.Errorf("rcode = %d, want %d", rcode, rc)
			}
			if records != nil {
				t.Error("records should be nil for error rcode")
			}
		})
	}
}

func TestParseAXFRResponse_EmptyAnswer(t *testing.T) {
	msg := buildTestDNSResponse(0, 0, nil)
	records, rcode, _ := parseAXFRResponse(msg)
	if rcode != 0 {
		t.Errorf("rcode = %d, want 0", rcode)
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
}

func TestParseAXFRResponse_WithQuestion(t *testing.T) {
	answers := []testDNSRR{
		{name: "example.com", rtype: 1, ttl: 300, rdata: []byte{10, 0, 0, 1}},
	}
	msg := buildTestDNSResponse(0, 1, answers)

	records, rcode, _ := parseAXFRResponse(msg)
	if rcode != 0 {
		t.Fatalf("rcode = %d, want 0", rcode)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if !strings.Contains(records[0].data, "10.0.0.1") {
		t.Errorf("data %q should contain IP", records[0].data)
	}
}

func TestParseAXFRResponse_TruncatedRdata(t *testing.T) {
	// Build response with RDLEN claiming more data than available
	var msg []byte
	msg = binary.BigEndian.AppendUint16(msg, 0x1234)
	msg = binary.BigEndian.AppendUint16(msg, 0x8000)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)

	msg = append(msg, 4)
	msg = append(msg, []byte("test")...)
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint32(msg, 300)
	msg = binary.BigEndian.AppendUint16(msg, 100) // claims 100 bytes
	msg = append(msg, 1, 2, 3, 4)                 // only 4 bytes

	// Should not panic
	records, _, _ := parseAXFRResponse(msg)
	_ = records
}

func TestDnsCommand_ZoneTransferMissingServer(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action: "zone-transfer",
		Target: "example.com",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error without server, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "server") {
		t.Errorf("error should mention server: %s", result.Output)
	}
}

func TestDnsCommand_AXFRAlias(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action: "axfr",
		Target: "example.com",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should hit the zone-transfer handler (and fail due to missing server)
	if result.Status != "error" {
		t.Errorf("expected error for axfr without server, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "server") {
		t.Errorf("error should mention server: %s", result.Output)
	}
}

func TestBuildAndDecode_RoundTrip(t *testing.T) {
	domain := "test.local"
	query := buildAXFRQuery(domain)

	// Decode the domain name from the query
	name := decodeDNSName(query, 12)
	if name != domain {
		t.Errorf("round-trip: got %q, want %q", name, domain)
	}

	// Verify skip matches
	endOffset := skipDNSName(query, 12)
	// After the name, we should have QTYPE + QCLASS (4 bytes) = end of query
	if endOffset+4 != len(query) {
		t.Errorf("skipDNSName returned %d, expected end at %d (len=%d)", endOffset, len(query)-4, len(query))
	}
}

func TestBuildAXFRQuery_DifferentDomains(t *testing.T) {
	q1 := buildAXFRQuery("example.com")
	q2 := buildAXFRQuery("test.org")
	// "example.com" = 13 bytes in wire format, "test.org" = 10 bytes
	if len(q1) == len(q2) {
		t.Error("different-length domains should produce different-length queries")
	}
}

func TestDnsCommand_WildcardNonexistentDomain(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "wildcard",
		Target:  "thisdomain.doesnotexist.invalid",
		Timeout: 3,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Wildcard DNS check") {
		t.Error("expected wildcard header in output")
	}
	// A nonexistent TLD should not have wildcard DNS
	if !strings.Contains(result.Output, "No wildcard detected") {
		t.Errorf("expected no wildcard for .invalid TLD, got: %s", result.Output)
	}
}

// --- DNS Action Coverage Tests ---
// These tests exercise the remaining DNS action branches (SRV, MX, NS, TXT, CNAME, ALL, DC)
// using well-known public domains. Each test accepts both success and error
// to handle environments where DNS resolution may be restricted.

func TestDnsCommand_MXAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "mx",
		Target:  "google.com",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status == "success" {
		if !strings.Contains(result.Output, "MX records") {
			t.Errorf("expected MX records header, got %q", result.Output)
		}
	}
	// Accept error in restricted environments
}

func TestDnsCommand_NSAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "ns",
		Target:  "google.com",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status == "success" {
		if !strings.Contains(result.Output, "NS records") {
			t.Errorf("expected NS records header, got %q", result.Output)
		}
	}
}

func TestDnsCommand_TXTAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "txt",
		Target:  "google.com",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status == "success" {
		if !strings.Contains(result.Output, "TXT records") {
			t.Errorf("expected TXT records header, got %q", result.Output)
		}
	}
}

func TestDnsCommand_CNAMEAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "cname",
		Target:  "www.google.com",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// CNAME may succeed or fail depending on DNS configuration
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q", result.Status)
	}
	if result.Status == "success" && !strings.Contains(result.Output, "CNAME") {
		t.Errorf("expected CNAME in output, got %q", result.Output)
	}
}

func TestDnsCommand_SRVActionDomain(t *testing.T) {
	cmd := &DnsCommand{}
	// Query SRV for a domain (defaults to _ldap._tcp)
	params, _ := json.Marshal(dnsArgs{
		Action:  "srv",
		Target:  "google.com",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// SRV for google.com likely errors (no _ldap._tcp), which is fine
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q", result.Status)
	}
}

func TestDnsCommand_SRVActionFull(t *testing.T) {
	cmd := &DnsCommand{}
	// Full SRV record name starting with _
	params, _ := json.Marshal(dnsArgs{
		Action:  "srv",
		Target:  "_http._tcp.google.com",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q", result.Status)
	}
	if result.Status == "success" && !strings.Contains(result.Output, "SRV records") {
		t.Errorf("expected SRV records header, got %q", result.Output)
	}
}

func TestDnsCommand_AllAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "all",
		Target:  "google.com",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for 'all' action, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "All DNS records") {
		t.Errorf("expected All DNS records header, got %q", result.Output)
	}
}

func TestDnsCommand_DCAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "dc",
		Target:  "google.com",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// DC discovery likely fails for non-AD domain, which is expected
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q", result.Status)
	}
}

func TestDnsCommand_CustomServer(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "resolve",
		Target:  "google.com",
		Server:  "8.8.8.8",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status == "success" {
		if !strings.Contains(result.Output, "A/AAAA records") {
			t.Errorf("expected records header, got %q", result.Output)
		}
	}
}

func TestDnsCommand_CustomServerWithPort(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "resolve",
		Target:  "google.com",
		Server:  "8.8.8.8:53",
		Timeout: 5,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// May or may not succeed depending on network
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q", result.Status)
	}
}

func TestDnsCommand_DefaultTimeout(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "resolve",
		Target:  "localhost",
		Timeout: 0, // should default to 5
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
}

// --- Benchmarks ---

func BenchmarkDecodeDNSName(b *testing.B) {
	var msg []byte
	for _, label := range []string{"dc01", "subdomain", "example", "com"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeDNSName(msg, 0)
	}
}

func BenchmarkBuildAXFRQuery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buildAXFRQuery("subdomain.example.com")
	}
}

func BenchmarkParseAXFRResponse(b *testing.B) {
	answers := make([]testDNSRR, 10)
	for i := range answers {
		answers[i] = testDNSRR{
			name:  fmt.Sprintf("host%d.example.com", i),
			rtype: 1,
			ttl:   300,
			rdata: []byte{10, 0, 0, byte(i + 1)},
		}
	}
	msg := buildTestDNSResponse(0, 0, answers)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseAXFRResponse(msg)
	}
}

func TestDecodeDNSName_LabelExceedsData(t *testing.T) {
	// Label length byte claims 20 but only 3 bytes follow — covers line 658-659
	msg := []byte{20, 'a', 'b', 'c'} // labelLen=20 but offset+labelLen > len(msg)
	name := decodeDNSName(msg, 0)
	if name != "." {
		t.Errorf("expected '.' for truncated label, got %q", name)
	}
}

func TestSkipDNSName_NoTerminator(t *testing.T) {
	// Data runs out without null terminator or pointer — covers skipDNSName line 682
	msg := []byte{3, 'a', 'b', 'c', 4, 'x', 'y', 'z', 'w'} // no null at end
	got := skipDNSName(msg, 0)
	if got < len(msg) {
		t.Errorf("expected offset >= %d (past end), got %d", len(msg), got)
	}
}
