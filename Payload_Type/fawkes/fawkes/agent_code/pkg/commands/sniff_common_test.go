package commands

import (
	"encoding/binary"
	"testing"
)

func TestSniffApplyDefaults_DefaultDuration(t *testing.T) {
	params := &sniffParams{}
	sniffApplyDefaults(params)
	if params.Duration != 30 {
		t.Errorf("default duration = %d, want 30", params.Duration)
	}
}

func TestSniffApplyDefaults_NegativeDuration(t *testing.T) {
	params := &sniffParams{Duration: -1}
	sniffApplyDefaults(params)
	if params.Duration != 30 {
		t.Errorf("negative duration should default to 30, got %d", params.Duration)
	}
}

func TestSniffApplyDefaults_ExcessiveDuration(t *testing.T) {
	params := &sniffParams{Duration: 600}
	sniffApplyDefaults(params)
	if params.Duration != 300 {
		t.Errorf("excessive duration should cap at 300, got %d", params.Duration)
	}
}

func TestSniffApplyDefaults_ValidDuration(t *testing.T) {
	params := &sniffParams{Duration: 60}
	sniffApplyDefaults(params)
	if params.Duration != 60 {
		t.Errorf("valid duration should be preserved, got %d", params.Duration)
	}
}

func TestSniffApplyDefaults_DefaultMaxBytes(t *testing.T) {
	params := &sniffParams{}
	sniffApplyDefaults(params)
	if params.MaxBytes != 50*1024*1024 {
		t.Errorf("default max_bytes = %d, want %d", params.MaxBytes, 50*1024*1024)
	}
}

func TestSniffApplyDefaults_DefaultPorts(t *testing.T) {
	params := &sniffParams{}
	ports := sniffApplyDefaults(params)
	expected := []uint16{21, 53, 80, 88, 110, 143, 389, 445, 8080}
	if len(ports) != len(expected) {
		t.Fatalf("default ports count = %d, want %d", len(ports), len(expected))
	}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port[%d] = %d, want %d", i, p, expected[i])
		}
	}
}

func TestSniffApplyDefaults_CustomPorts(t *testing.T) {
	params := &sniffParams{Ports: "80,443,8080"}
	ports := sniffApplyDefaults(params)
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	expected := []uint16{80, 443, 8080}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port[%d] = %d, want %d", i, p, expected[i])
		}
	}
}

func TestSniffApplyDefaults_PortsWithSpaces(t *testing.T) {
	params := &sniffParams{Ports: " 80 , 443 , 8080 "}
	ports := sniffApplyDefaults(params)
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports (spaces trimmed), got %d", len(ports))
	}
}

func TestSniffApplyDefaults_InvalidPortsFallsBackToDefaults(t *testing.T) {
	params := &sniffParams{Ports: "0,abc,70000,-1"}
	ports := sniffApplyDefaults(params)
	if len(ports) != 9 {
		t.Errorf("all-invalid ports should fall back to defaults (9 ports), got %d: %v", len(ports), ports)
	}
}

func TestSniffApplyDefaults_MixedValidInvalidPorts(t *testing.T) {
	params := &sniffParams{Ports: "80,abc,443,0,8080"}
	ports := sniffApplyDefaults(params)
	if len(ports) != 3 {
		t.Fatalf("expected 3 valid ports, got %d: %v", len(ports), ports)
	}
}

func TestSniffMatchPort(t *testing.T) {
	ports := []uint16{80, 443, 8080}

	tests := []struct {
		srcPort uint16
		dstPort uint16
		want    bool
	}{
		{12345, 80, true},
		{80, 12345, true},
		{443, 12345, true},
		{12345, 443, true},
		{12345, 8080, true},
		{12345, 22, false},
		{22, 12345, false},
		{0, 0, false},
	}

	for _, tt := range tests {
		got := sniffMatchPort(ports, tt.srcPort, tt.dstPort)
		if got != tt.want {
			t.Errorf("sniffMatchPort(ports, %d, %d) = %v, want %v", tt.srcPort, tt.dstPort, got, tt.want)
		}
	}
}

func TestSniffMatchPort_EmptyPorts(t *testing.T) {
	got := sniffMatchPort(nil, 80, 443)
	if got {
		t.Error("empty ports should never match")
	}
}

func buildIPv4TCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	ihl := 20
	tcpHdrLen := 20
	totalLen := ihl + tcpHdrLen + len(payload)

	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // version=4, IHL=5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = 6 // TCP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	// TCP header
	tcp := pkt[ihl:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50 // data offset = 5 (20 bytes)

	copy(pkt[ihl+tcpHdrLen:], payload)
	return pkt
}

func buildIPv4UDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	ihl := 20
	udpHdrLen := 8
	totalLen := ihl + udpHdrLen + len(payload)

	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	udp := pkt[ihl:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdrLen+len(payload)))

	copy(pkt[ihl+udpHdrLen:], payload)
	return pkt
}

func TestSniffParseIPPacket_TCP(t *testing.T) {
	src := [4]byte{192, 168, 1, 100}
	dst := [4]byte{10, 0, 0, 1}
	payload := []byte("GET / HTTP/1.1\r\n")

	pkt := buildIPv4TCPPacket(src, dst, 54321, 80, payload)
	result := sniffParseIPPacket(pkt)

	if result == nil {
		t.Fatal("expected non-nil result for valid TCP packet")
	}
	if result.Meta.SrcIP != "192.168.1.100" {
		t.Errorf("SrcIP = %q, want 192.168.1.100", result.Meta.SrcIP)
	}
	if result.Meta.DstIP != "10.0.0.1" {
		t.Errorf("DstIP = %q, want 10.0.0.1", result.Meta.DstIP)
	}
	if result.Meta.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want 54321", result.Meta.SrcPort)
	}
	if result.Meta.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", result.Meta.DstPort)
	}
	if string(result.Payload) != string(payload) {
		t.Errorf("Payload = %q, want %q", result.Payload, payload)
	}
}

func TestSniffParseIPPacket_UDP(t *testing.T) {
	src := [4]byte{192, 168, 1, 50}
	dst := [4]byte{8, 8, 8, 8}
	payload := []byte{0x00, 0x01, 0x00, 0x00} // DNS-like

	pkt := buildIPv4UDPPacket(src, dst, 12345, 53, payload)
	result := sniffParseIPPacket(pkt)

	if result == nil {
		t.Fatal("expected non-nil result for valid UDP packet")
	}
	if result.Meta.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", result.Meta.SrcPort)
	}
	if result.Meta.DstPort != 53 {
		t.Errorf("DstPort = %d, want 53", result.Meta.DstPort)
	}
	if len(result.Payload) != len(payload) {
		t.Errorf("payload len = %d, want %d", len(result.Payload), len(payload))
	}
}

func TestSniffParseIPPacket_TooShort(t *testing.T) {
	result := sniffParseIPPacket([]byte{0x45, 0x00, 0x00})
	if result != nil {
		t.Error("packet < 20 bytes should return nil")
	}
}

func TestSniffParseIPPacket_NonTCPUDP(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[9] = 1 // ICMP
	result := sniffParseIPPacket(pkt)
	if result != nil {
		t.Error("non-TCP/UDP protocol should return nil")
	}
}

func TestSniffParseIPPacket_EmptyPayload(t *testing.T) {
	pkt := buildIPv4TCPPacket([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1234, 80, nil)
	result := sniffParseIPPacket(pkt)
	if result != nil {
		t.Error("empty payload should return nil")
	}
}

func TestSniffParseIPPacket_InvalidIHL(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x41 // IHL=1 (4 bytes, too small)
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[9] = 6

	result := sniffParseIPPacket(pkt)
	if result != nil {
		t.Error("invalid IHL should return nil")
	}
}

func TestSniffPCAPCollector_AddAndBuild(t *testing.T) {
	collector := newSniffPCAPCollector(1024 * 1024)
	data1 := []byte("packet one")
	data2 := []byte("packet two")

	collector.addPacket(data1)
	collector.addPacket(data2)

	pcap := collector.buildPCAP(1) // Ethernet link type

	// Verify PCAP global header
	if len(pcap) < 24 {
		t.Fatalf("PCAP too short: %d bytes", len(pcap))
	}
	magic := binary.LittleEndian.Uint32(pcap[0:4])
	if magic != 0xA1B2C3D4 {
		t.Errorf("magic = 0x%X, want 0xA1B2C3D4", magic)
	}
	versionMajor := binary.LittleEndian.Uint16(pcap[4:6])
	versionMinor := binary.LittleEndian.Uint16(pcap[6:8])
	if versionMajor != 2 || versionMinor != 4 {
		t.Errorf("version = %d.%d, want 2.4", versionMajor, versionMinor)
	}
	linkType := binary.LittleEndian.Uint32(pcap[20:24])
	if linkType != 1 {
		t.Errorf("link type = %d, want 1", linkType)
	}

	// Verify packets exist (24 header + 16 per-packet header + data for each)
	expectedSize := 24 + 16 + len(data1) + 16 + len(data2)
	if len(pcap) != expectedSize {
		t.Errorf("PCAP size = %d, want %d", len(pcap), expectedSize)
	}

	// Verify first packet header
	pktInclLen := binary.LittleEndian.Uint32(pcap[24+8 : 24+12])
	if pktInclLen != uint32(len(data1)) {
		t.Errorf("first packet incl_len = %d, want %d", pktInclLen, len(data1))
	}

	// Verify first packet data
	pktData := pcap[24+16 : 24+16+len(data1)]
	if string(pktData) != string(data1) {
		t.Errorf("first packet data = %q, want %q", pktData, data1)
	}
}

func TestSniffPCAPCollector_SizeLimit(t *testing.T) {
	collector := newSniffPCAPCollector(20)
	collector.addPacket([]byte("12345678901234567890")) // exactly 20 bytes
	collector.addPacket([]byte("dropped"))              // should be dropped

	pcap := collector.buildPCAP(1)
	// Should only have 1 packet: 24 (header) + 16 (pkt header) + 20 (data)
	if len(pcap) != 24+16+20 {
		t.Errorf("PCAP size = %d, want %d (one packet only)", len(pcap), 24+16+20)
	}
}

func TestSniffPCAPCollector_EmptyBuild(t *testing.T) {
	collector := newSniffPCAPCollector(1024)
	pcap := collector.buildPCAP(1)
	if len(pcap) != 24 {
		t.Errorf("empty PCAP should be 24 bytes (header only), got %d", len(pcap))
	}
}

func TestSniffPCAPCollector_DataIsCopied(t *testing.T) {
	collector := newSniffPCAPCollector(1024)
	data := []byte("original")
	collector.addPacket(data)

	// Modify original data — should not affect stored packet
	data[0] = 'X'

	pcap := collector.buildPCAP(1)
	pktData := pcap[24+16 : 24+16+8]
	if string(pktData) != "original" {
		t.Errorf("stored data should be a copy, got %q", pktData)
	}
}
