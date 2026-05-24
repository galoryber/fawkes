package commands

import (
	"time"
)

// sniffExtractLDAP extracts credentials from LDAP simple bind requests (RFC 4511).
// A BindRequest is an ASN.1 SEQUENCE containing:
//   messageID (INTEGER), BindRequest (APPLICATION 0) containing:
//     version (INTEGER), name (OCTET STRING = DN), authentication CHOICE:
//       simple (CONTEXT 0 = password)
// We look for the ASN.1 pattern without a full DER parser.
func sniffExtractLDAP(payload []byte, meta *packetMeta) *sniffCredential {
	// Only check LDAP ports
	if meta.DstPort != 389 && meta.DstPort != 636 && meta.SrcPort != 389 && meta.SrcPort != 636 {
		return nil
	}

	if len(payload) < 14 {
		return nil
	}

	// LDAP messages start with a SEQUENCE tag (0x30)
	if payload[0] != 0x30 {
		return nil
	}

	// Parse outer SEQUENCE length
	data, ok := derSkipTL(payload)
	if !ok || len(data) < 10 {
		return nil
	}

	// Skip messageID (INTEGER tag 0x02)
	if data[0] != 0x02 {
		return nil
	}
	data, ok = derSkipTLV(data)
	if !ok || len(data) < 7 {
		return nil
	}

	// BindRequest is APPLICATION 0 (tag 0x60)
	if data[0] != 0x60 {
		return nil
	}
	data, ok = derSkipTL(data)
	if !ok || len(data) < 5 {
		return nil
	}

	// version (INTEGER) — must be 3 for LDAPv3
	if data[0] != 0x02 {
		return nil
	}
	data, ok = derSkipTLV(data)
	if !ok || len(data) < 3 {
		return nil
	}

	// name (OCTET STRING tag 0x04) — the DN (Distinguished Name)
	if data[0] != 0x04 {
		return nil
	}
	dn, data, ok := derReadOctetString(data)
	if !ok || len(data) < 2 {
		return nil
	}

	// authentication CHOICE — simple bind is CONTEXT 0 (tag 0x80)
	if data[0] != 0x80 {
		return nil // Not simple bind (could be SASL = 0xA3)
	}
	password, _, ok := derReadContextString(data)
	if !ok {
		return nil
	}

	// Skip empty or anonymous binds
	if len(dn) == 0 || len(password) == 0 {
		return nil
	}

	return &sniffCredential{
		Protocol:  "ldap",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  string(dn),
		Password:  string(password),
		Timestamp: time.Now().Unix(),
	}
}

// derSkipTL skips tag and length, returning the value portion of a TLV.
func derSkipTL(data []byte) ([]byte, bool) {
	if len(data) < 2 {
		return nil, false
	}
	// Skip tag byte
	lenByte := data[1]
	if lenByte < 0x80 {
		// Short form: length is the byte itself
		start := 2
		if start+int(lenByte) > len(data) {
			return data[start:], true // Return what we have
		}
		return data[start:], true
	}
	// Long form: lenByte & 0x7F = number of length bytes
	numBytes := int(lenByte & 0x7F)
	if numBytes == 0 || numBytes > 4 || 2+numBytes > len(data) {
		return nil, false
	}
	start := 2 + numBytes
	if start > len(data) {
		return nil, false
	}
	return data[start:], true
}

// derSkipTLV skips an entire TLV element, returning data after it.
func derSkipTLV(data []byte) ([]byte, bool) {
	if len(data) < 2 {
		return nil, false
	}
	lenByte := data[1]
	if lenByte < 0x80 {
		end := 2 + int(lenByte)
		if end > len(data) {
			return nil, false
		}
		return data[end:], true
	}
	numBytes := int(lenByte & 0x7F)
	if numBytes == 0 || numBytes > 4 || 2+numBytes > len(data) {
		return nil, false
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[2+i])
	}
	end := 2 + numBytes + length
	if end > len(data) {
		return nil, false
	}
	return data[end:], true
}

// derReadOctetString reads an OCTET STRING (tag 0x04) and returns its value and remaining data.
func derReadOctetString(data []byte) (value []byte, rest []byte, ok bool) {
	if len(data) < 2 || data[0] != 0x04 {
		return nil, nil, false
	}
	lenByte := data[1]
	if lenByte < 0x80 {
		end := 2 + int(lenByte)
		if end > len(data) {
			return nil, nil, false
		}
		return data[2:end], data[end:], true
	}
	numBytes := int(lenByte & 0x7F)
	if numBytes == 0 || numBytes > 4 || 2+numBytes > len(data) {
		return nil, nil, false
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[2+i])
	}
	start := 2 + numBytes
	end := start + length
	if end > len(data) {
		return nil, nil, false
	}
	return data[start:end], data[end:], true
}

// derReadContextString reads a CONTEXT-specific string (tag 0x80) and returns value and rest.
func derReadContextString(data []byte) (value []byte, rest []byte, ok bool) {
	if len(data) < 2 || data[0] != 0x80 {
		return nil, nil, false
	}
	lenByte := data[1]
	if lenByte < 0x80 {
		end := 2 + int(lenByte)
		if end > len(data) {
			return nil, nil, false
		}
		return data[2:end], data[end:], true
	}
	numBytes := int(lenByte & 0x7F)
	if numBytes == 0 || numBytes > 4 || 2+numBytes > len(data) {
		return nil, nil, false
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[2+i])
	}
	start := 2 + numBytes
	end := start + length
	if end > len(data) {
		return nil, nil, false
	}
	return data[start:end], data[end:], true
}
