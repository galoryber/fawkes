package socks

import (
	"encoding/base64"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

// --- UDP ASSOCIATE Tests ---

func TestHandleMessages_UDPAssociate(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Build SOCKS5 UDP ASSOCIATE request: VER=5 CMD=3 RSV=0 ATYP=1 DST.ADDR=0.0.0.0 DST.PORT=0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	b64 := base64.StdEncoding.EncodeToString(req)

	m.HandleMessages([]structs.SocksMsg{{ServerId: 1, Data: b64}})

	// Give a moment for the relay to initialize
	time.Sleep(50 * time.Millisecond)

	// Verify a UDP relay was created
	m.mu.Lock()
	_, exists := m.udpRelays[1]
	m.mu.Unlock()

	if !exists {
		t.Fatal("UDP ASSOCIATE should create a relay entry")
	}

	// Verify success reply was queued
	msgs := m.DrainOutbound()
	if len(msgs) == 0 {
		t.Fatal("UDP ASSOCIATE should queue a success reply")
	}

	replyData, err := base64.StdEncoding.DecodeString(msgs[0].Data)
	if err != nil {
		t.Fatalf("Failed to decode reply: %v", err)
	}
	if replyData[0] != 0x05 || replyData[1] != 0x00 {
		t.Errorf("Expected success reply (VER=5 REP=0), got VER=%d REP=%d", replyData[0], replyData[1])
	}
}

func TestHandleMessages_UDPRelay(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Start a UDP echo server
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	echoConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoConn.Close()
	echoPort := echoConn.LocalAddr().(*net.UDPAddr).Port

	// Echo server goroutine
	go func() {
		buf := make([]byte, 1024)
		n, addr, err := echoConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		echoConn.WriteToUDP(buf[:n], addr)
	}()

	// Create UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	b64 := base64.StdEncoding.EncodeToString(req)
	m.HandleMessages([]structs.SocksMsg{{ServerId: 10, Data: b64}})
	time.Sleep(50 * time.Millisecond)

	// Drain the success reply
	m.DrainOutbound()

	// Build SOCKS5 UDP datagram: RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) + DATA
	payload := []byte("hello-udp")
	udpFrame := make([]byte, 10+len(payload))
	// RSV = 0x0000, FRAG = 0x00, ATYP = 0x01 (IPv4)
	udpFrame[3] = 0x01
	copy(udpFrame[4:8], net.ParseIP("127.0.0.1").To4())
	binary.BigEndian.PutUint16(udpFrame[8:10], uint16(echoPort))
	copy(udpFrame[10:], payload)

	b64UDP := base64.StdEncoding.EncodeToString(udpFrame)
	m.HandleMessages([]structs.SocksMsg{{ServerId: 10, Data: b64UDP}})

	// Wait for echo response
	time.Sleep(200 * time.Millisecond)

	// Check for response in outbound
	msgs := m.DrainOutbound()
	if len(msgs) == 0 {
		t.Fatal("Expected UDP echo response in outbound")
	}

	responseData, err := base64.StdEncoding.DecodeString(msgs[0].Data)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Response should have SOCKS5 UDP header + payload
	if len(responseData) < 10 {
		t.Fatalf("Response too short: %d bytes", len(responseData))
	}
	// Extract payload from response (skip IPv4 header = 10 bytes)
	respPayload := responseData[10:]
	if string(respPayload) != "hello-udp" {
		t.Errorf("Expected 'hello-udp' in response, got '%s'", string(respPayload))
	}
}

func TestHandleMessages_UDPFragmentDropped(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Create UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	m.HandleMessages([]structs.SocksMsg{{ServerId: 20, Data: base64.StdEncoding.EncodeToString(req)}})
	time.Sleep(50 * time.Millisecond)
	m.DrainOutbound() // drain success reply

	// Build fragmented UDP datagram (FRAG != 0)
	udpFrame := make([]byte, 15)
	udpFrame[2] = 0x01 // FRAG = 1 (non-zero = fragmented)
	udpFrame[3] = 0x01 // ATYP = IPv4
	copy(udpFrame[4:8], net.ParseIP("127.0.0.1").To4())
	binary.BigEndian.PutUint16(udpFrame[8:10], 53)
	copy(udpFrame[10:], []byte("data!"))

	m.HandleMessages([]structs.SocksMsg{{ServerId: 20, Data: base64.StdEncoding.EncodeToString(udpFrame)}})
	time.Sleep(50 * time.Millisecond)

	// Should have no outbound (fragment silently dropped)
	msgs := m.DrainOutbound()
	if len(msgs) != 0 {
		t.Errorf("Fragmented UDP should be silently dropped, got %d messages", len(msgs))
	}
}

func TestCloseUDPRelay(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Create UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	m.HandleMessages([]structs.SocksMsg{{ServerId: 30, Data: base64.StdEncoding.EncodeToString(req)}})
	time.Sleep(50 * time.Millisecond)

	m.mu.Lock()
	_, exists := m.udpRelays[30]
	m.mu.Unlock()
	if !exists {
		t.Fatal("Relay should exist after UDP ASSOCIATE")
	}

	// Close via exit message
	m.HandleMessages([]structs.SocksMsg{{ServerId: 30, Exit: true}})
	time.Sleep(50 * time.Millisecond)

	m.mu.Lock()
	_, existsAfter := m.udpRelays[30]
	m.mu.Unlock()
	if existsAfter {
		t.Error("Relay should be removed after exit")
	}
}

func TestUDPAssociate_DomainAddress(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Start UDP echo server
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	echoConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoConn.Close()
	echoPort := echoConn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 1024)
		n, addr, _ := echoConn.ReadFromUDP(buf)
		echoConn.WriteToUDP(buf[:n], addr)
	}()

	// Create UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	m.HandleMessages([]structs.SocksMsg{{ServerId: 40, Data: base64.StdEncoding.EncodeToString(req)}})
	time.Sleep(50 * time.Millisecond)
	m.DrainOutbound()

	// Build UDP datagram with domain address
	domain := "localhost"
	payload := []byte("domain-test")
	udpFrame := make([]byte, 4+1+len(domain)+2+len(payload))
	udpFrame[3] = 0x03 // ATYP = domain
	udpFrame[4] = byte(len(domain))
	copy(udpFrame[5:5+len(domain)], domain)
	binary.BigEndian.PutUint16(udpFrame[5+len(domain):], uint16(echoPort))
	copy(udpFrame[5+len(domain)+2:], payload)

	m.HandleMessages([]structs.SocksMsg{{ServerId: 40, Data: base64.StdEncoding.EncodeToString(udpFrame)}})
	time.Sleep(200 * time.Millisecond)

	msgs := m.DrainOutbound()
	if len(msgs) == 0 {
		t.Fatal("Expected UDP echo response for domain address")
	}
}

func TestManagerClose_CleansUpUDPRelays(t *testing.T) {
	m := NewManager()

	// Create UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	m.HandleMessages([]structs.SocksMsg{{ServerId: 50, Data: base64.StdEncoding.EncodeToString(req)}})
	time.Sleep(50 * time.Millisecond)

	m.mu.Lock()
	relayCount := len(m.udpRelays)
	m.mu.Unlock()
	if relayCount == 0 {
		t.Fatal("Should have 1 relay before Close()")
	}

	m.Close()

	m.mu.Lock()
	relayCountAfter := len(m.udpRelays)
	m.mu.Unlock()
	if relayCountAfter != 0 {
		t.Errorf("Close() should clean up UDP relays, still have %d", relayCountAfter)
	}
}

func TestUDPAssociate_EmptyPayloadIgnored(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Create UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	m.HandleMessages([]structs.SocksMsg{{ServerId: 60, Data: base64.StdEncoding.EncodeToString(req)}})
	time.Sleep(50 * time.Millisecond)
	m.DrainOutbound()

	// Build UDP datagram with no payload (just header)
	udpFrame := make([]byte, 10)
	udpFrame[3] = 0x01 // ATYP = IPv4
	copy(udpFrame[4:8], net.ParseIP("127.0.0.1").To4())
	binary.BigEndian.PutUint16(udpFrame[8:10], 53)

	m.HandleMessages([]structs.SocksMsg{{ServerId: 60, Data: base64.StdEncoding.EncodeToString(udpFrame)}})
	time.Sleep(50 * time.Millisecond)

	msgs := m.DrainOutbound()
	if len(msgs) != 0 {
		t.Errorf("Empty payload should be ignored, got %d messages", len(msgs))
	}
}

func TestUDPConstants(t *testing.T) {
	if udpAssociateCommand != 0x03 {
		t.Errorf("udpAssociateCommand should be 0x03, got 0x%02x", udpAssociateCommand)
	}
	if udpMaxPacket != 65535 {
		t.Errorf("udpMaxPacket should be 65535, got %d", udpMaxPacket)
	}
	if udpIdleTimeout != 2*time.Minute {
		t.Errorf("udpIdleTimeout should be 2m, got %v", udpIdleTimeout)
	}
}
