package socks

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

// --- NewManager Tests ---

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	if m.connections == nil {
		t.Error("NewManager() connections map is nil")
	}
	if len(m.connections) != 0 {
		t.Errorf("NewManager() connections should be empty, got %d", len(m.connections))
	}
}

// --- DrainOutbound Tests ---

func TestDrainOutbound_Empty(t *testing.T) {
	m := NewManager()
	msgs := m.DrainOutbound()
	if msgs != nil {
		t.Errorf("DrainOutbound() on empty manager should return nil, got %v", msgs)
	}
}

func TestDrainOutbound_ClearsQueue(t *testing.T) {
	m := NewManager()
	m.mu.Lock()
	m.outbound = append(m.outbound, structs.SocksMsg{ServerId: 1, Data: "test", Exit: false})
	m.outbound = append(m.outbound, structs.SocksMsg{ServerId: 2, Data: "test2", Exit: true})
	m.mu.Unlock()

	msgs := m.DrainOutbound()
	if len(msgs) != 2 {
		t.Fatalf("DrainOutbound() should return 2 messages, got %d", len(msgs))
	}
	if msgs[0].ServerId != 1 {
		t.Errorf("First message ServerId = %d, want 1", msgs[0].ServerId)
	}
	if msgs[1].ServerId != 2 {
		t.Errorf("Second message ServerId = %d, want 2", msgs[1].ServerId)
	}

	// Queue should be empty after drain
	msgs2 := m.DrainOutbound()
	if msgs2 != nil {
		t.Errorf("DrainOutbound() after drain should return nil, got %v", msgs2)
	}
}

func TestDrainOutbound_Concurrent(t *testing.T) {
	m := NewManager()

	// Fill some messages
	m.mu.Lock()
	for i := 0; i < 100; i++ {
		m.outbound = append(m.outbound, structs.SocksMsg{ServerId: uint32(i)})
	}
	m.mu.Unlock()

	// Drain concurrently
	var wg sync.WaitGroup
	results := make([][]structs.SocksMsg, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = m.DrainOutbound()
		}(i)
	}
	wg.Wait()

	// Exactly one goroutine should get all messages, rest should get nil
	totalMsgs := 0
	for _, r := range results {
		totalMsgs += len(r)
	}
	if totalMsgs != 100 {
		t.Errorf("Total messages across all drains = %d, want 100", totalMsgs)
	}
}

// --- sendReply Tests ---

func TestSendReply_Success(t *testing.T) {
	m := NewManager()
	m.sendReply(42, replySuccess)

	msgs := m.DrainOutbound()
	if len(msgs) != 1 {
		t.Fatalf("sendReply should produce 1 message, got %d", len(msgs))
	}
	if msgs[0].ServerId != 42 {
		t.Errorf("Reply ServerId = %d, want 42", msgs[0].ServerId)
	}
	if msgs[0].Exit {
		t.Error("Reply should not be an exit message")
	}

	data, err := base64.StdEncoding.DecodeString(msgs[0].Data)
	if err != nil {
		t.Fatalf("Failed to decode reply data: %v", err)
	}
	if len(data) != 10 {
		t.Fatalf("Reply data length = %d, want 10", len(data))
	}
	if data[0] != socksVersion {
		t.Errorf("Reply version = %d, want %d", data[0], socksVersion)
	}
	if data[1] != replySuccess {
		t.Errorf("Reply code = %d, want %d", data[1], replySuccess)
	}
	if data[3] != addrTypeIPv4 {
		t.Errorf("Reply address type = %d, want %d", data[3], addrTypeIPv4)
	}
}

func TestSendReply_ConnectionRefused(t *testing.T) {
	m := NewManager()
	m.sendReply(99, replyConnectionRefused)

	msgs := m.DrainOutbound()
	if len(msgs) != 1 {
		t.Fatalf("sendReply should produce 1 message, got %d", len(msgs))
	}

	data, _ := base64.StdEncoding.DecodeString(msgs[0].Data)
	if data[1] != replyConnectionRefused {
		t.Errorf("Reply code = %d, want %d", data[1], replyConnectionRefused)
	}
}

// --- queueExit Tests ---

func TestQueueExit(t *testing.T) {
	m := NewManager()
	m.queueExit(55)

	msgs := m.DrainOutbound()
	if len(msgs) != 1 {
		t.Fatalf("queueExit should produce 1 message, got %d", len(msgs))
	}
	if msgs[0].ServerId != 55 {
		t.Errorf("Exit ServerId = %d, want 55", msgs[0].ServerId)
	}
	if !msgs[0].Exit {
		t.Error("Exit message should have Exit=true")
	}
	if msgs[0].Data != "" {
		t.Errorf("Exit message data should be empty, got %q", msgs[0].Data)
	}
}

// --- closeConnection Tests ---

func TestCloseConnection_Existing(t *testing.T) {
	m := NewManager()

	// Create a test listener and connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	// Accept server side
	srvConn, _ := ln.Accept()
	defer srvConn.Close()

	m.mu.Lock()
	m.connections[10] = conn
	m.mu.Unlock()

	m.closeConnection(10)

	m.mu.Lock()
	_, exists := m.connections[10]
	m.mu.Unlock()
	if exists {
		t.Error("Connection should have been removed from map after close")
	}
}

func TestCloseConnection_NonExisting(t *testing.T) {
	m := NewManager()
	// Should not panic
	m.closeConnection(999)
}

// --- HandleMessages Tests ---

func TestHandleMessages_ExitMessage(t *testing.T) {
	m := NewManager()

	// Create a test connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	srvConn, _ := ln.Accept()
	defer srvConn.Close()

	m.mu.Lock()
	m.connections[20] = conn
	m.mu.Unlock()

	// Send exit message
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 20, Exit: true},
	})

	m.mu.Lock()
	_, exists := m.connections[20]
	m.mu.Unlock()
	if exists {
		t.Error("Exit message should close and remove connection")
	}
}

func TestHandleMessages_InvalidBase64NewConnection(t *testing.T) {
	m := NewManager()

	// Invalid base64 should result in exit being queued
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 30, Data: "not-valid-base64!!!", Exit: false},
	})

	msgs := m.DrainOutbound()
	if len(msgs) != 1 {
		t.Fatalf("Should produce 1 exit message, got %d", len(msgs))
	}
	if !msgs[0].Exit {
		t.Error("Should queue exit on invalid base64")
	}
}

func TestHandleMessages_InvalidSOCKSVersion(t *testing.T) {
	m := NewManager()

	// SOCKS4 request (version 0x04 instead of 0x05)
	data := []byte{0x04, connectCommand, 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50}
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 31, Data: b64, Exit: false},
	})

	msgs := m.DrainOutbound()
	// Should get a connection refused reply + an exit message
	if len(msgs) != 2 {
		t.Fatalf("Invalid SOCKS version should produce 2 messages (reply + exit), got %d", len(msgs))
	}
	// First should be the reply
	replyData, _ := base64.StdEncoding.DecodeString(msgs[0].Data)
	if replyData[1] != replyConnectionRefused {
		t.Errorf("Reply code = %d, want %d", replyData[1], replyConnectionRefused)
	}
	// Second should be exit
	if !msgs[1].Exit {
		t.Error("Second message should be exit")
	}
}

func TestHandleMessages_InvalidCommand(t *testing.T) {
	m := NewManager()

	// SOCKS5 BIND command (0x02) instead of CONNECT (0x01)
	data := []byte{socksVersion, 0x02, 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50}
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 32, Data: b64, Exit: false},
	})

	msgs := m.DrainOutbound()
	if len(msgs) != 2 {
		t.Fatalf("Invalid command should produce 2 messages, got %d", len(msgs))
	}
}

func TestHandleMessages_TooShortData(t *testing.T) {
	m := NewManager()

	// Only 3 bytes (minimum is 4)
	data := []byte{socksVersion, connectCommand, 0x00}
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 33, Data: b64, Exit: false},
	})

	msgs := m.DrainOutbound()
	if len(msgs) != 1 {
		t.Fatalf("Too-short data should produce 1 exit message, got %d", len(msgs))
	}
	if !msgs[0].Exit {
		t.Error("Should queue exit on too-short data")
	}
}

func TestHandleMessages_UnsupportedAddressType(t *testing.T) {
	m := NewManager()

	// Unknown address type 0xFF
	data := []byte{socksVersion, connectCommand, 0x00, 0xFF, 127, 0, 0, 1, 0x00, 0x50}
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 34, Data: b64, Exit: false},
	})

	msgs := m.DrainOutbound()
	if len(msgs) != 2 {
		t.Fatalf("Unsupported address type should produce 2 messages, got %d", len(msgs))
	}
}

// --- SOCKS5 CONNECT with IPv4 to a real listener ---

func TestHandleMessages_IPv4Connect(t *testing.T) {
	// Start a TCP listener to accept connections
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	// Build SOCKS5 CONNECT request for 127.0.0.1:<port>
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeIPv4, 127, 0, 0, 1}
	data = append(data, portBytes...)
	b64 := base64.StdEncoding.EncodeToString(data)

	m := NewManager()
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 100, Data: b64, Exit: false},
	})

	// Accept the incoming connection on the listener side
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	srvConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Expected connection to listener, got error: %v", err)
	}
	defer srvConn.Close()

	// Give the reply time to be queued
	time.Sleep(50 * time.Millisecond)

	msgs := m.DrainOutbound()
	if len(msgs) < 1 {
		t.Fatalf("Should have at least 1 reply message, got %d", len(msgs))
	}

	replyData, err := base64.StdEncoding.DecodeString(msgs[0].Data)
	if err != nil {
		t.Fatalf("Failed to decode reply: %v", err)
	}
	if replyData[1] != replySuccess {
		t.Errorf("Reply code = %d, want %d (success)", replyData[1], replySuccess)
	}

	// Verify connection is stored
	m.mu.Lock()
	_, exists := m.connections[100]
	m.mu.Unlock()
	if !exists {
		t.Error("Connection should be stored in manager after successful connect")
	}

	// Clean up
	m.closeConnection(100)
}

// --- SOCKS5 CONNECT with domain name ---

func TestHandleMessages_DomainConnect(t *testing.T) {
	// Start a listener on localhost
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	// Build SOCKS5 CONNECT request with domain "localhost"
	domain := "localhost"
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeDomain, byte(len(domain))}
	data = append(data, []byte(domain)...)
	data = append(data, portBytes...)
	b64 := base64.StdEncoding.EncodeToString(data)

	m := NewManager()
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 101, Data: b64, Exit: false},
	})

	// Accept the connection
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	srvConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Expected connection to listener, got error: %v", err)
	}
	defer srvConn.Close()

	time.Sleep(50 * time.Millisecond)

	msgs := m.DrainOutbound()
	if len(msgs) < 1 {
		t.Fatal("Should have at least 1 reply message")
	}

	replyData, _ := base64.StdEncoding.DecodeString(msgs[0].Data)
	if replyData[1] != replySuccess {
		t.Errorf("Reply code = %d, want success", replyData[1])
	}

	m.closeConnection(101)
}

// --- SOCKS5 CONNECT to unreachable host ---

func TestHandleMessages_ConnectionRefused(t *testing.T) {
	m := NewManager()

	// Connect to a port that's definitely not listening (high port)
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeIPv4, 127, 0, 0, 1}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 1) // port 1 — almost certainly not listening
	data = append(data, portBytes...)
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 102, Data: b64, Exit: false},
	})

	// Wait for connection attempt to fail
	time.Sleep(200 * time.Millisecond)

	msgs := m.DrainOutbound()
	if len(msgs) < 2 {
		t.Fatalf("Connection refused should produce at least 2 messages (reply + exit), got %d", len(msgs))
	}

	replyData, _ := base64.StdEncoding.DecodeString(msgs[0].Data)
	if replyData[1] != replyConnectionRefused {
		t.Errorf("Reply code = %d, want %d (refused)", replyData[1], replyConnectionRefused)
	}
	if !msgs[1].Exit {
		t.Error("Second message should be exit")
	}
}

// --- ForwardData Tests ---

func TestForwardData_ToConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	srvConn, _ := ln.Accept()
	defer srvConn.Close()

	m := NewManager()
	m.mu.Lock()
	m.connections[200] = conn
	m.mu.Unlock()

	testData := []byte("hello SOCKS")
	b64 := base64.StdEncoding.EncodeToString(testData)

	m.forwardData(200, conn, b64)

	// Read from the server side
	buf := make([]byte, 256)
	srvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := srvConn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read forwarded data: %v", err)
	}
	if string(buf[:n]) != "hello SOCKS" {
		t.Errorf("Forwarded data = %q, want %q", string(buf[:n]), "hello SOCKS")
	}

	m.closeConnection(200)
}

func TestForwardData_EmptyData(t *testing.T) {
	m := NewManager()
	// Should not panic with nil connection and empty data
	m.forwardData(999, nil, "")
}

func TestForwardData_InvalidBase64(t *testing.T) {
	m := NewManager()
	// Invalid base64 should not panic — just log and return
	m.forwardData(300, nil, "!!!not-valid-base64!!!")
	// If we get here without panic, the decode error path worked
}

func TestForwardData_WriteFailed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	srvConn, _ := ln.Accept()
	srvConn.Close() // Close server side

	m := NewManager()
	m.mu.Lock()
	m.connections[301] = conn
	m.mu.Unlock()

	// Close the client side too to ensure write fails
	conn.Close()

	testData := base64.StdEncoding.EncodeToString([]byte("write fail"))
	m.forwardData(301, conn, testData)

	// After write failure, the connection should be cleaned up
	time.Sleep(50 * time.Millisecond)
	m.mu.Lock()
	_, exists := m.connections[301]
	m.mu.Unlock()
	if exists {
		t.Error("Connection should have been removed after write failure")
	}
}

// --- readFromConnection data relay test ---

func TestReadFromConnection_RelaysData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	srvConn, _ := ln.Accept()
	defer srvConn.Close()

	m := NewManager()
	m.mu.Lock()
	m.connections[300] = conn
	m.mu.Unlock()

	// Start reader
	go m.readFromConnection(300, conn)

	// Write data from server side
	testPayload := "data from server"
	_, err = srvConn.Write([]byte(testPayload))
	if err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	msgs := m.DrainOutbound()
	if len(msgs) < 1 {
		t.Fatal("Should have at least 1 outbound message with relayed data")
	}

	decoded, err := base64.StdEncoding.DecodeString(msgs[0].Data)
	if err != nil {
		t.Fatalf("Failed to decode relayed data: %v", err)
	}
	if string(decoded) != testPayload {
		t.Errorf("Relayed data = %q, want %q", string(decoded), testPayload)
	}

	// Close server side to trigger exit
	srvConn.Close()
	time.Sleep(100 * time.Millisecond)

	exitMsgs := m.DrainOutbound()
	foundExit := false
	for _, msg := range exitMsgs {
		if msg.Exit && msg.ServerId == 300 {
			foundExit = true
			break
		}
	}
	if !foundExit {
		t.Error("Should queue exit message when connection closes")
	}
}

// --- IPv4 address parsing edge cases ---

func TestHandleMessages_IPv4TooShort(t *testing.T) {
	m := NewManager()

	// IPv4 requires 10 bytes total, provide only 8
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeIPv4, 127, 0, 0, 1}
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 40, Data: b64, Exit: false},
	})

	msgs := m.DrainOutbound()
	if len(msgs) < 1 {
		t.Fatal("Should produce messages for too-short IPv4 data")
	}
	// Should get refused reply + exit
	foundExit := false
	for _, msg := range msgs {
		if msg.Exit {
			foundExit = true
		}
	}
	if !foundExit {
		t.Error("Should queue exit for too-short IPv4")
	}
}

// --- Domain address parsing edge cases ---

func TestHandleMessages_DomainTooShort(t *testing.T) {
	m := NewManager()

	// Domain with length byte saying 10 but only 3 bytes of domain
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeDomain, 10, 'a', 'b', 'c'}
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 41, Data: b64, Exit: false},
	})

	msgs := m.DrainOutbound()
	foundExit := false
	for _, msg := range msgs {
		if msg.Exit {
			foundExit = true
		}
	}
	if !foundExit {
		t.Error("Should queue exit for truncated domain data")
	}
}

// --- IPv6 address parsing ---

func TestHandleMessages_IPv6TooShort(t *testing.T) {
	m := NewManager()

	// IPv6 requires 22 bytes total, provide only 10
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeIPv6, 0, 0, 0, 0, 0, 0}
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 42, Data: b64, Exit: false},
	})

	msgs := m.DrainOutbound()
	foundExit := false
	for _, msg := range msgs {
		if msg.Exit {
			foundExit = true
		}
	}
	if !foundExit {
		t.Error("Should queue exit for too-short IPv6")
	}
}

func TestHandleMessages_IPv6Connect(t *testing.T) {
	// Start a listener on IPv6 loopback
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available, skipping")
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	// Build SOCKS5 CONNECT for [::1]
	ipv6 := net.ParseIP("::1").To16()
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeIPv6}
	data = append(data, ipv6...)
	data = append(data, portBytes...)
	b64 := base64.StdEncoding.EncodeToString(data)

	m := NewManager()
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 103, Data: b64, Exit: false},
	})

	ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	srvConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Expected IPv6 connection, got error: %v", err)
	}
	defer srvConn.Close()

	time.Sleep(50 * time.Millisecond)
	msgs := m.DrainOutbound()
	if len(msgs) < 1 {
		t.Fatal("Should have reply message for IPv6 connect")
	}
	replyData, _ := base64.StdEncoding.DecodeString(msgs[0].Data)
	if replyData[1] != replySuccess {
		t.Errorf("IPv6 reply code = %d, want success", replyData[1])
	}

	m.closeConnection(103)
}

// --- Full lifecycle test: connect, forward, read, close ---

func TestFullLifecycle(t *testing.T) {
	// Start echo server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n]) // echo back
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	// Step 1: CONNECT
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeIPv4, 127, 0, 0, 1}
	data = append(data, portBytes...)
	b64 := base64.StdEncoding.EncodeToString(data)

	m := NewManager()
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 500, Data: b64, Exit: false},
	})

	time.Sleep(100 * time.Millisecond)

	// Verify connect reply
	msgs := m.DrainOutbound()
	if len(msgs) < 1 {
		t.Fatal("Should have connect reply")
	}
	replyData, _ := base64.StdEncoding.DecodeString(msgs[0].Data)
	if replyData[1] != replySuccess {
		t.Fatalf("Connect should succeed, got reply code %d", replyData[1])
	}

	// Step 2: Forward data
	testMsg := "Hello echo server"
	fwdB64 := base64.StdEncoding.EncodeToString([]byte(testMsg))
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 500, Data: fwdB64, Exit: false},
	})

	// Wait for echo
	time.Sleep(200 * time.Millisecond)

	// Step 3: Read echoed data
	echoMsgs := m.DrainOutbound()
	if len(echoMsgs) < 1 {
		t.Fatal("Should have echo data")
	}
	echoData, _ := base64.StdEncoding.DecodeString(echoMsgs[0].Data)
	if string(echoData) != testMsg {
		t.Errorf("Echo = %q, want %q", string(echoData), testMsg)
	}

	// Step 4: Close connection
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 500, Exit: true},
	})

	m.mu.Lock()
	_, exists := m.connections[500]
	m.mu.Unlock()
	if exists {
		t.Error("Connection should be removed after exit")
	}
}

// --- Domain parsing minimum length ---

func TestHandleMessages_DomainMinLength(t *testing.T) {
	m := NewManager()

	// Domain type but only 4 bytes total (need at least 5 for domain length byte)
	data := []byte{socksVersion, connectCommand, 0x00, addrTypeDomain}
	b64 := base64.StdEncoding.EncodeToString(data)

	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 43, Data: b64, Exit: false},
	})

	msgs := m.DrainOutbound()
	foundExit := false
	for _, msg := range msgs {
		if msg.Exit {
			foundExit = true
		}
	}
	if !foundExit {
		t.Error("Should queue exit for domain with no length byte")
	}
}

// --- Constants verification ---

func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      interface{}
		want     interface{}
	}{
		{"socksVersion", socksVersion, byte(0x05)},
		{"connectCommand", connectCommand, byte(0x01)},
		{"addrTypeIPv4", addrTypeIPv4, byte(0x01)},
		{"addrTypeDomain", addrTypeDomain, byte(0x03)},
		{"addrTypeIPv6", addrTypeIPv6, byte(0x04)},
		{"replySuccess", replySuccess, byte(0x00)},
		{"replyConnectionRefused", replyConnectionRefused, byte(0x05)},
		{"readBufSize", readBufSize, 32 * 1024},
		{"dialTimeout", dialTimeout, 10 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if fmt.Sprintf("%v", tt.got) != fmt.Sprintf("%v", tt.want) {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}
