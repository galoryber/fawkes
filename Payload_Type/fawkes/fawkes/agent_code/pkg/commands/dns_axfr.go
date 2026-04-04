package commands

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// dnsAXFR performs a DNS zone transfer (AXFR) via raw TCP DNS protocol.
// AXFR is a powerful recon technique that can reveal all DNS records in a zone.
// Requires a DNS server parameter — zone transfers use TCP, not the system resolver.
func dnsAXFR(ctx context.Context, args dnsArgs) structs.CommandResult {
	if args.Server == "" {
		return errorResult("Error: -server is required for zone transfers (e.g., -server 192.168.1.1)")
	}

	server := args.Server
	if !strings.Contains(server, ":") {
		server += ":53"
	}

	// Build AXFR query (DNS wire format)
	domain := args.Target
	query := buildAXFRQuery(domain)

	// TCP DNS uses 2-byte length prefix
	tcpMsg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(tcpMsg[:2], uint16(len(query)))
	copy(tcpMsg[2:], query)

	// Connect via TCP
	d := net.Dialer{Timeout: time.Duration(args.Timeout) * time.Second}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return errorf("Error connecting to %s: %v", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(args.Timeout) * time.Second))

	// Send query
	if _, err := conn.Write(tcpMsg); err != nil {
		return errorf("Error sending AXFR query: %v", err)
	}

	// Read all response messages (AXFR may span multiple TCP messages)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Zone transfer (AXFR) for %s from %s\n", domain, server))
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	totalRecords := 0
	soaCount := 0

	for {
		// Read 2-byte length prefix
		lenBuf := make([]byte, 2)
		if _, err := dnsReadFull(conn, lenBuf); err != nil {
			if totalRecords > 0 {
				break // Normal end
			}
			return errorResult(sb.String() + fmt.Sprintf("\n[!] Error reading response: %v\n", err))
		}
		msgLen := binary.BigEndian.Uint16(lenBuf)
		if msgLen == 0 {
			break
		}

		// Read DNS message
		msgBuf := make([]byte, msgLen)
		if _, err := dnsReadFull(conn, msgBuf); err != nil {
			break
		}

		// Parse DNS response
		records, rcode, soaInMsg := parseAXFRResponse(msgBuf)
		if rcode != 0 {
			rcodeNames := map[int]string{
				1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
				4: "NOTIMP", 5: "REFUSED", 9: "NOTAUTH",
			}
			name := rcodeNames[rcode]
			if name == "" {
				name = fmt.Sprintf("RCODE_%d", rcode)
			}
			sb.WriteString(fmt.Sprintf("\n[!] Zone transfer refused: %s\n", name))
			if rcode == 5 {
				sb.WriteString("[*] Zone transfers are typically restricted to authorized secondary DNS servers\n")
			}
			return errorResult(sb.String())
		}

		for _, r := range records {
			sb.WriteString(fmt.Sprintf("  %-40s %-8s %s\n", r.name, r.rtype, r.data))
			totalRecords++
		}
		soaCount += soaInMsg

		// AXFR ends with the second SOA record
		if soaCount >= 2 {
			break
		}
	}

	if totalRecords == 0 {
		sb.WriteString("\n[!] No records received — zone transfer may be denied\n")
		return errorResult(sb.String())
	}

	sb.WriteString(fmt.Sprintf("\n[+] Zone transfer complete: %d records\n", totalRecords))
	return successResult(sb.String())
}

// dnsReadFull reads exactly len(buf) bytes from conn.
func dnsReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

type dnsRecord struct {
	name  string
	rtype string
	data  string
}

// buildAXFRQuery constructs a DNS AXFR query in wire format.
func buildAXFRQuery(domain string) []byte {
	var buf []byte

	// Header (12 bytes)
	txid := uint16(rand.Intn(65536))
	buf = binary.BigEndian.AppendUint16(buf, txid)   // Transaction ID
	buf = binary.BigEndian.AppendUint16(buf, 0x0000) // Flags: standard query
	buf = binary.BigEndian.AppendUint16(buf, 1)      // Questions: 1
	buf = binary.BigEndian.AppendUint16(buf, 0)      // Answers: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)      // Authority: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)      // Additional: 0

	// Question section: encode domain name
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // Root label

	buf = binary.BigEndian.AppendUint16(buf, 252) // QTYPE: AXFR
	buf = binary.BigEndian.AppendUint16(buf, 1)   // QCLASS: IN

	return buf
}

// parseAXFRResponse parses a DNS response message and extracts resource records.
func parseAXFRResponse(msg []byte) (records []dnsRecord, rcode int, soaCount int) {
	if len(msg) < 12 {
		return nil, 0, 0
	}

	// Header
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode = int(flags & 0x000F)
	if rcode != 0 {
		return nil, rcode, 0
	}

	qdCount := binary.BigEndian.Uint16(msg[4:6])
	anCount := binary.BigEndian.Uint16(msg[6:8])

	offset := 12

	// Skip questions
	for i := uint16(0); i < qdCount; i++ {
		offset = skipDNSName(msg, offset)
		if offset+4 > len(msg) {
			return nil, 0, 0
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answers
	for i := uint16(0); i < anCount; i++ {
		if offset >= len(msg) {
			break
		}
		name := decodeDNSName(msg, offset)
		offset = skipDNSName(msg, offset)
		if offset+10 > len(msg) {
			break
		}

		rtype := binary.BigEndian.Uint16(msg[offset:])
		offset += 2
		_ = binary.BigEndian.Uint16(msg[offset:]) // class
		offset += 2
		ttl := binary.BigEndian.Uint32(msg[offset:])
		offset += 4
		rdlen := binary.BigEndian.Uint16(msg[offset:])
		offset += 2

		if offset+int(rdlen) > len(msg) {
			break
		}

		rdataOffset := offset
		offset += int(rdlen)

		rtypeName, dataStr := formatRR(rtype, msg[rdataOffset:rdataOffset+int(rdlen)], msg, rdataOffset, ttl)
		records = append(records, dnsRecord{name: name, rtype: rtypeName, data: dataStr})
		if rtype == 6 { // SOA
			soaCount++
		}
	}

	return records, 0, soaCount
}

// formatRR formats a resource record's type and data for display.
func formatRR(rtype uint16, rdata []byte, msg []byte, rdataOffset int, ttl uint32) (string, string) {
	ttlStr := fmt.Sprintf("TTL=%d", ttl)
	switch rtype {
	case 1: // A
		if len(rdata) == 4 {
			return "A", fmt.Sprintf("%d.%d.%d.%d  %s", rdata[0], rdata[1], rdata[2], rdata[3], ttlStr)
		}
	case 2: // NS
		return "NS", decodeDNSName(msg, rdataOffset) + "  " + ttlStr
	case 5: // CNAME
		return "CNAME", decodeDNSName(msg, rdataOffset) + "  " + ttlStr
	case 6: // SOA
		mname := decodeDNSName(msg, rdataOffset)
		nextOff := skipDNSName(msg, rdataOffset)
		rname := decodeDNSName(msg, nextOff)
		nextOff = skipDNSName(msg, nextOff)
		serial := uint32(0)
		if nextOff+4 <= len(msg) {
			serial = binary.BigEndian.Uint32(msg[nextOff:])
		}
		return "SOA", fmt.Sprintf("%s %s serial=%d", mname, rname, serial)
	case 15: // MX
		if len(rdata) >= 2 {
			pref := binary.BigEndian.Uint16(rdata[:2])
			mx := decodeDNSName(msg, rdataOffset+2)
			return "MX", fmt.Sprintf("%s pref=%d  %s", mx, pref, ttlStr)
		}
	case 16: // TXT
		if len(rdata) > 0 {
			txtLen := int(rdata[0])
			if txtLen <= len(rdata)-1 {
				return "TXT", fmt.Sprintf("\"%s\"  %s", string(rdata[1:1+txtLen]), ttlStr)
			}
		}
	case 28: // AAAA
		if len(rdata) == 16 {
			ip := net.IP(rdata)
			return "AAAA", ip.String() + "  " + ttlStr
		}
	case 33: // SRV
		if len(rdata) >= 6 {
			priority := binary.BigEndian.Uint16(rdata[:2])
			weight := binary.BigEndian.Uint16(rdata[2:4])
			port := binary.BigEndian.Uint16(rdata[4:6])
			target := decodeDNSName(msg, rdataOffset+6)
			return "SRV", fmt.Sprintf("%s:%d priority=%d weight=%d  %s", target, port, priority, weight, ttlStr)
		}
	}
	return fmt.Sprintf("TYPE%d", rtype), fmt.Sprintf("(%d bytes)  %s", len(rdata), ttlStr)
}

// decodeDNSName decodes a DNS name with compression pointer support.
func decodeDNSName(msg []byte, offset int) string {
	var parts []string
	visited := make(map[int]bool)
	for offset < len(msg) {
		if visited[offset] {
			break
		}
		visited[offset] = true

		labelLen := int(msg[offset])
		if labelLen == 0 {
			break
		}
		if labelLen&0xC0 == 0xC0 {
			if offset+1 >= len(msg) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(msg[offset:offset+2])) & 0x3FFF
			offset = ptr
			continue
		}
		offset++
		if offset+labelLen > len(msg) {
			break
		}
		parts = append(parts, string(msg[offset:offset+labelLen]))
		offset += labelLen
	}
	if len(parts) == 0 {
		return "."
	}
	return strings.Join(parts, ".")
}

// skipDNSName advances past a DNS name in wire format.
func skipDNSName(msg []byte, offset int) int {
	for offset < len(msg) {
		labelLen := int(msg[offset])
		if labelLen == 0 {
			return offset + 1
		}
		if labelLen&0xC0 == 0xC0 {
			return offset + 2
		}
		offset += 1 + labelLen
	}
	return offset
}
