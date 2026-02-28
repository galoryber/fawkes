package commands

import (
	"encoding/binary"
	"encoding/json"
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
