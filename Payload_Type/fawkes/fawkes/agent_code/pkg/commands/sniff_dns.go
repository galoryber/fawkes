package commands

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// DNS query extraction — extracts queried domain names from DNS packets.
// DNS uses a standard binary format on port 53 (UDP or TCP).
func sniffExtractDNS(payload []byte, meta *packetMeta) *sniffCredential {
	if meta.DstPort != 53 && meta.SrcPort != 53 {
		return nil
	}

	// DNS header is 12 bytes minimum
	if len(payload) < 12 {
		return nil
	}

	// Flags: check if this is a standard query (QR=0, Opcode=0)
	flags := binary.BigEndian.Uint16(payload[2:4])
	isQuery := (flags & 0x8000) == 0 // QR bit
	if !isQuery {
		return nil // Only capture queries, not responses
	}

	qdCount := binary.BigEndian.Uint16(payload[4:6])
	if qdCount == 0 || qdCount > 10 { // Sanity check
		return nil
	}

	// Parse the first question
	offset := 12
	name, newOffset := sniffParseDNSName(payload, offset)
	if name == "" || newOffset <= offset {
		return nil
	}

	// Read QTYPE (2 bytes) after the name
	if newOffset+4 > len(payload) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(payload[newOffset : newOffset+2])

	qtypeStr := "UNKNOWN"
	switch qtype {
	case 1:
		qtypeStr = "A"
	case 2:
		qtypeStr = "NS"
	case 5:
		qtypeStr = "CNAME"
	case 6:
		qtypeStr = "SOA"
	case 15:
		qtypeStr = "MX"
	case 16:
		qtypeStr = "TXT"
	case 28:
		qtypeStr = "AAAA"
	case 33:
		qtypeStr = "SRV"
	case 252:
		qtypeStr = "AXFR"
	case 255:
		qtypeStr = "ANY"
	}

	return &sniffCredential{
		Protocol:  "dns",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  name,
		Detail:    fmt.Sprintf("type=%s", qtypeStr),
		Timestamp: time.Now().Unix(),
	}
}

// sniffParseDNSName reads a DNS domain name from a packet, handling label compression.
func sniffParseDNSName(data []byte, offset int) (string, int) {
	var parts []string
	visited := make(map[int]bool) // Prevent infinite loops from malformed compression
	originalOffset := offset
	jumped := false

	for offset < len(data) {
		if visited[offset] {
			break
		}
		visited[offset] = true

		labelLen := int(data[offset])
		if labelLen == 0 {
			offset++
			break
		}

		// Compression pointer (top 2 bits = 11)
		if labelLen&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF
			if !jumped {
				originalOffset = offset + 2
				jumped = true
			}
			offset = ptr
			continue
		}

		offset++
		end := offset + labelLen
		if end > len(data) {
			break
		}
		parts = append(parts, string(data[offset:end]))
		offset = end
	}

	if len(parts) == 0 {
		return "", originalOffset
	}

	if jumped {
		return strings.Join(parts, "."), originalOffset
	}
	return strings.Join(parts, "."), offset
}
