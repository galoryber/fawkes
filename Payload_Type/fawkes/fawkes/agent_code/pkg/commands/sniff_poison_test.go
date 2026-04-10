package commands

import (
	"net"
	"testing"
)

func TestParsePoisonProtocols(t *testing.T) {
	tests := []struct {
		input    string
		expected map[string]bool
	}{
		{"", map[string]bool{"llmnr": true, "nbtns": true}},
		{"llmnr", map[string]bool{"llmnr": true}},
		{"nbtns", map[string]bool{"nbtns": true}},
		{"mdns", map[string]bool{"mdns": true}},
		{"llmnr,nbtns", map[string]bool{"llmnr": true, "nbtns": true}},
		{"LLMNR,NBTNS,MDNS", map[string]bool{"llmnr": true, "nbtns": true, "mdns": true}},
		{"invalid", map[string]bool{"llmnr": true, "nbtns": true}}, // defaults
		{"llmnr, nbtns", map[string]bool{"llmnr": true, "nbtns": true}}, // with spaces
	}

	for _, tc := range tests {
		result := parsePoisonProtocols(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("parsePoisonProtocols(%q) got %v, expected %v", tc.input, result, tc.expected)
			continue
		}
		for k := range tc.expected {
			if !result[k] {
				t.Errorf("parsePoisonProtocols(%q) missing protocol %q", tc.input, k)
			}
		}
	}
}

func TestExtractLLMNRQueryName(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected string
	}{
		{
			"valid LLMNR query for WPAD",
			buildTestLLMNRQuery("WPAD"),
			"WPAD",
		},
		{
			"valid LLMNR query for fileserver",
			buildTestLLMNRQuery("fileserver"),
			"fileserver",
		},
		{
			"too short",
			[]byte{0x00, 0x01},
			"",
		},
		{
			"empty name",
			make([]byte, 13),
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractLLMNRQueryName(tc.packet)
			if result != tc.expected {
				t.Errorf("extractLLMNRQueryName() = %q, expected %q", result, tc.expected)
			}
		})
	}
}

func TestExtractNBTNSQueryName(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected string
	}{
		{
			"valid NBT-NS query for WPAD",
			buildTestNBTNSQuery("WPAD"),
			"WPAD",
		},
		{
			"too short",
			[]byte{0x00},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractNBTNSQueryName(tc.packet)
			if result != tc.expected {
				t.Errorf("extractNBTNSQueryName() = %q, expected %q", result, tc.expected)
			}
		})
	}
}

func TestBuildLLMNRResponse(t *testing.T) {
	query := buildTestLLMNRQuery("WPAD")
	responseIP := net.ParseIP("10.0.0.5")

	resp, err := buildLLMNRResponse(query, responseIP)
	if err != nil {
		t.Fatalf("buildLLMNRResponse() error: %v", err)
	}

	// Check transaction ID matches
	if resp[0] != query[0] || resp[1] != query[1] {
		t.Error("Transaction ID mismatch")
	}

	// Check QR flag is set (response)
	if resp[2]&0x80 == 0 {
		t.Error("QR flag not set in response")
	}

	// Check ANCOUNT = 1
	if resp[6] != 0 || resp[7] != 1 {
		t.Error("ANCOUNT should be 1")
	}

	// Check response contains our IP
	found := false
	for i := 0; i <= len(resp)-4; i++ {
		if resp[i] == 10 && resp[i+1] == 0 && resp[i+2] == 0 && resp[i+3] == 5 {
			found = true
			break
		}
	}
	if !found {
		t.Error("Response IP 10.0.0.5 not found in response")
	}
}

func TestBuildNBTNSResponse(t *testing.T) {
	query := buildTestNBTNSQuery("WPAD")
	responseIP := net.ParseIP("192.168.1.100")

	resp, err := buildNBTNSResponse(query, responseIP)
	if err != nil {
		t.Fatalf("buildNBTNSResponse() error: %v", err)
	}

	// Check QR flag is set
	if resp[2]&0x80 == 0 {
		t.Error("QR flag not set in response")
	}

	// Check response contains our IP
	ip := responseIP.To4()
	found := false
	for i := 0; i <= len(resp)-4; i++ {
		if resp[i] == ip[0] && resp[i+1] == ip[1] && resp[i+2] == ip[2] && resp[i+3] == ip[3] {
			found = true
			break
		}
	}
	if !found {
		t.Error("Response IP not found in NBT-NS response")
	}
}

func TestBuildLLMNRResponseErrors(t *testing.T) {
	// Too short
	_, err := buildLLMNRResponse([]byte{0x00}, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Error("Expected error for short packet")
	}

	// IPv6 not supported
	query := buildTestLLMNRQuery("test")
	_, err = buildLLMNRResponse(query, net.ParseIP("::1"))
	if err == nil {
		t.Error("Expected error for IPv6")
	}
}

// Helper: build a test LLMNR query packet
func buildTestLLMNRQuery(name string) []byte {
	packet := make([]byte, 0, 64)
	// Header: TX ID, Flags=0 (query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	packet = append(packet, 0xAB, 0xCD) // TX ID
	packet = append(packet, 0x00, 0x00) // Flags: query
	packet = append(packet, 0x00, 0x01) // QDCOUNT=1
	packet = append(packet, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // AN/NS/AR=0
	// Question: name
	packet = append(packet, byte(len(name)))
	packet = append(packet, []byte(name)...)
	packet = append(packet, 0x00)       // null terminator
	packet = append(packet, 0x00, 0x01) // QTYPE A
	packet = append(packet, 0x00, 0x01) // QCLASS IN
	return packet
}

// Helper: build a test NBT-NS query packet
func buildTestNBTNSQuery(name string) []byte {
	packet := make([]byte, 0, 64)
	// Header
	packet = append(packet, 0xAB, 0xCD) // TX ID
	packet = append(packet, 0x01, 0x10) // Flags: query, broadcast
	packet = append(packet, 0x00, 0x01) // QDCOUNT=1
	packet = append(packet, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Encode name in NetBIOS format (pad to 16 chars with spaces, then encode)
	padded := make([]byte, 16)
	copy(padded, []byte(name))
	for i := len(name); i < 16; i++ {
		padded[i] = 0x20 // space padding
	}
	packet = append(packet, 32) // label length = 32
	for _, ch := range padded {
		packet = append(packet, 'A'+(ch>>4), 'A'+(ch&0x0F))
	}
	packet = append(packet, 0x00)       // null terminator
	packet = append(packet, 0x00, 0x20) // QTYPE NB
	packet = append(packet, 0x00, 0x01) // QCLASS IN
	return packet
}
