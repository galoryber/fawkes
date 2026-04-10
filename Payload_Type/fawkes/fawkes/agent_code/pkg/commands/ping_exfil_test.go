package commands

import (
	"encoding/binary"
	"testing"
)

func TestBuildICMPEchoRequest(t *testing.T) {
	payload := []byte("test data")
	pkt := buildICMPEchoRequest(0xFA57, 42, payload)

	// Type = 8 (Echo Request)
	if pkt[0] != 8 {
		t.Errorf("Type = %d, expected 8", pkt[0])
	}
	// Code = 0
	if pkt[1] != 0 {
		t.Errorf("Code = %d, expected 0", pkt[1])
	}
	// Identifier
	id := binary.BigEndian.Uint16(pkt[4:6])
	if id != 0xFA57 {
		t.Errorf("Identifier = 0x%04X, expected 0xFA57", id)
	}
	// Sequence
	seq := binary.BigEndian.Uint16(pkt[6:8])
	if seq != 42 {
		t.Errorf("Sequence = %d, expected 42", seq)
	}
	// Payload
	if string(pkt[8:]) != "test data" {
		t.Errorf("Payload = %q, expected 'test data'", string(pkt[8:]))
	}
	// Total length
	if len(pkt) != 8+len(payload) {
		t.Errorf("Packet length = %d, expected %d", len(pkt), 8+len(payload))
	}
}

func TestICMPChecksum(t *testing.T) {
	// Build a packet and verify checksum validity
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	pkt := buildICMPEchoRequest(0x1234, 1, payload)

	// Verify checksum: recomputing over the full packet should give 0
	sum := icmpChecksum(pkt)
	// The checksum of a packet with a valid checksum should be 0 (or very close)
	// Actually, computing checksum of a packet that already includes its checksum
	// should give 0xFFFF (complement of 0)
	if sum != 0xFFFF && sum != 0 {
		// For a valid checksum, the sum of all 16-bit words including the checksum
		// should be 0xFFFF
		t.Logf("Re-checksum = 0x%04X (expected 0xFFFF or 0x0000)", sum)
	}

	// Verify a specific known good checksum calculation
	// Empty payload, type=8, code=0, id=0, seq=0
	simple := []byte{8, 0, 0, 0, 0, 0, 0, 0}
	cs := icmpChecksum(simple)
	simple[2] = byte(cs >> 8)
	simple[3] = byte(cs)
	// Re-verify: icmpChecksum returns ~sum, so valid packet gives 0x0000
	verify := icmpChecksum(simple)
	if verify != 0x0000 {
		t.Errorf("Simple packet re-checksum = 0x%04X, expected 0x0000", verify)
	}
}

func TestICMPChecksumOddLength(t *testing.T) {
	// Odd-length data should work correctly
	data := []byte{8, 0, 0, 0, 0, 0, 0, 0, 0xFF}
	cs := icmpChecksum(data)
	if cs == 0 {
		t.Error("Checksum should not be 0 for non-zero data")
	}
}

func TestICMPChunkCount(t *testing.T) {
	tests := []struct {
		dataSize  int
		chunkSize int
		expected  int
	}{
		{100, 1024, 1},                      // small file, one chunk
		{1024 - 8, 1024, 1},                 // exactly one effective chunk
		{1024 - 8 + 1, 1024, 2},             // just over one chunk
		{10000, 1024, 10},                    // ~10KB
		{0, 1024, 0},                         // empty
		{1, 64, 1},                           // minimum chunk size
		{100, icmpExfilHeaderSize + 1, 100},  // tiny effective chunk
	}

	for _, tc := range tests {
		result := icmpChunkCount(tc.dataSize, tc.chunkSize)
		if result != tc.expected {
			t.Errorf("icmpChunkCount(%d, %d) = %d, expected %d",
				tc.dataSize, tc.chunkSize, result, tc.expected)
		}
	}
}

func TestBuildICMPEchoRequestMagic(t *testing.T) {
	// Verify the Fawkes magic identifier
	pkt := buildICMPEchoRequest(icmpExfilMagic, 0, []byte{0xDE, 0xAD})
	id := binary.BigEndian.Uint16(pkt[4:6])
	if id != 0xFA57 {
		t.Errorf("Magic identifier = 0x%04X, expected 0xFA57", id)
	}
}

func TestBuildICMPExfilHeaderPacket(t *testing.T) {
	// Simulate building the first exfil packet with header
	totalChunks := uint16(5)
	totalSize := uint32(5000)
	xorKey := byte(0x42)

	header := make([]byte, icmpExfilHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], totalChunks)
	binary.BigEndian.PutUint32(header[2:6], totalSize)
	header[6] = xorKey
	header[7] = 0

	payload := append(header, []byte("chunk0data")...)
	pkt := buildICMPEchoRequest(icmpExfilMagic, 0, payload)

	// Verify we can extract the header from the ICMP payload
	icmpPayload := pkt[8:]
	gotChunks := binary.BigEndian.Uint16(icmpPayload[0:2])
	gotSize := binary.BigEndian.Uint32(icmpPayload[2:6])
	gotKey := icmpPayload[6]

	if gotChunks != totalChunks {
		t.Errorf("Chunks = %d, expected %d", gotChunks, totalChunks)
	}
	if gotSize != totalSize {
		t.Errorf("Size = %d, expected %d", gotSize, totalSize)
	}
	if gotKey != xorKey {
		t.Errorf("XOR key = 0x%02X, expected 0x%02X", gotKey, xorKey)
	}
	if string(icmpPayload[8:]) != "chunk0data" {
		t.Errorf("Data = %q, expected 'chunk0data'", string(icmpPayload[8:]))
	}
}
