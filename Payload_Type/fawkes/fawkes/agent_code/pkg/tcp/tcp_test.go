package tcp

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

// --- Constructor ---

func TestNewTCPProfile(t *testing.T) {
	p := NewTCPProfile("0.0.0.0:7777", "dGVzdGtleQ==", true)
	if p == nil {
		t.Fatal("NewTCPProfile returned nil")
	}
	if p.BindAddress != "0.0.0.0:7777" {
		t.Errorf("Expected bind address '0.0.0.0:7777', got '%s'", p.BindAddress)
	}
	if p.EncryptionKey != "dGVzdGtleQ==" {
		t.Errorf("Expected encryption key 'dGVzdGtleQ==', got '%s'", p.EncryptionKey)
	}
	if !p.Debug {
		t.Error("Expected debug=true")
	}
	if p.childConns == nil {
		t.Error("childConns map not initialized")
	}
	if p.InboundDelegates == nil {
		t.Error("InboundDelegates channel not initialized")
	}
	if p.OutboundDelegates == nil {
		t.Error("OutboundDelegates channel not initialized")
	}
	if p.EdgeMessages == nil {
		t.Error("EdgeMessages channel not initialized")
	}
	if p.uuidMapping == nil {
		t.Error("uuidMapping map not initialized")
	}
}

func TestNewTCPProfile_EmptyParams(t *testing.T) {
	p := NewTCPProfile("", "", false)
	if p == nil {
		t.Fatal("NewTCPProfile returned nil with empty params")
	}
	if p.BindAddress != "" {
		t.Errorf("Expected empty bind address, got '%s'", p.BindAddress)
	}
}

// --- TCP Framing (sendTCP / recvTCP) ---

func TestSendRecvTCP_BasicMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := NewTCPProfile("", "", false)
	testMsg := []byte("hello tcp framing")

	// Send in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.sendTCP(client, testMsg)
	}()

	// Receive
	received, err := p.recvTCP(server)
	if err != nil {
		t.Fatalf("recvTCP failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("sendTCP failed: %v", err)
	}

	if string(received) != string(testMsg) {
		t.Errorf("Expected '%s', got '%s'", testMsg, received)
	}
}

func TestSendRecvTCP_EmptyMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := NewTCPProfile("", "", false)

	go func() {
		p.sendTCP(client, []byte{})
	}()

	received, err := p.recvTCP(server)
	if err != nil {
		t.Fatalf("recvTCP failed for empty message: %v", err)
	}
	if len(received) != 0 {
		t.Errorf("Expected empty message, got %d bytes", len(received))
	}
}

func TestSendRecvTCP_LargeMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := NewTCPProfile("", "", false)

	// 1MB message
	largeMsg := make([]byte, 1024*1024)
	rand.Read(largeMsg)

	go func() {
		p.sendTCP(client, largeMsg)
	}()

	received, err := p.recvTCP(server)
	if err != nil {
		t.Fatalf("recvTCP failed for large message: %v", err)
	}
	if len(received) != len(largeMsg) {
		t.Errorf("Expected %d bytes, got %d", len(largeMsg), len(received))
	}
}

func TestRecvTCP_MessageTooLarge(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := NewTCPProfile("", "", false)

	// Send a header indicating >10MB message
	go func() {
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 11*1024*1024) // 11MB
		client.Write(header)
	}()

	_, err := p.recvTCP(server)
	if err == nil {
		t.Error("Expected error for oversized message")
	}
}

func TestSendTCP_LengthHeader(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := NewTCPProfile("", "", false)
	testMsg := []byte("test123")

	go func() {
		p.sendTCP(client, testMsg)
	}()

	// Read raw: first 4 bytes = length header
	header := make([]byte, 4)
	io.ReadFull(server, header)
	length := binary.BigEndian.Uint32(header)

	if length != uint32(len(testMsg)) {
		t.Errorf("Expected length %d, got %d", len(testMsg), length)
	}

	// Read body
	body := make([]byte, length)
	io.ReadFull(server, body)
	if string(body) != string(testMsg) {
		t.Errorf("Expected '%s', got '%s'", testMsg, body)
	}
}

func TestRecvTCP_ClosedConnection(t *testing.T) {
	client, server := net.Pipe()
	p := NewTCPProfile("", "", false)

	client.Close() // Close before read

	_, err := p.recvTCP(server)
	if err == nil {
		t.Error("Expected error reading from closed connection")
	}
	server.Close()
}

func TestSendRecvTCP_MultipleMessages(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := NewTCPProfile("", "", false)
	messages := []string{"first", "second", "third"}

	go func() {
		for _, msg := range messages {
			p.sendTCP(client, []byte(msg))
		}
	}()

	for _, expected := range messages {
		received, err := p.recvTCP(server)
		if err != nil {
			t.Fatalf("recvTCP failed: %v", err)
		}
		if string(received) != expected {
			t.Errorf("Expected '%s', got '%s'", expected, received)
		}
	}
}

// --- Encryption ---

func generateTestKey() string {
	key := make([]byte, 32) // AES-256
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

func TestEncryptMessage_NoKey(t *testing.T) {
	p := NewTCPProfile("", "", false) // No encryption key
	msg := []byte("plaintext message")
	result := p.encryptMessage(msg)
	if string(result) != string(msg) {
		t.Error("Without key, encryptMessage should return original message")
	}
}

func TestEncryptMessage_WithKey(t *testing.T) {
	key := generateTestKey()
	p := NewTCPProfile("", key, false)
	msg := []byte("secret message")

	encrypted := p.encryptMessage(msg)
	if string(encrypted) == string(msg) {
		t.Error("Encrypted message should differ from plaintext")
	}

	// Encrypted format: IV (16) + ciphertext (padded) + HMAC (32)
	if len(encrypted) < 16+16+32 { // IV + at least one block + HMAC
		t.Errorf("Encrypted message too short: %d bytes", len(encrypted))
	}
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := generateTestKey()
	p := NewTCPProfile("", key, false)
	p.CallbackUUID = "12345678-1234-1234-1234-123456789012" // 36 chars

	testMessages := []string{
		"hello",
		"test message with some longer content",
		"",
		"exact block 1234", // 16 bytes exactly
	}

	for _, msg := range testMessages {
		encrypted := p.encryptMessage([]byte(msg))

		// The decryptResponse expects UUID prefix (36 bytes) before IV
		withUUID := append([]byte(p.CallbackUUID), encrypted...)

		decrypted, err := p.decryptResponse(withUUID)
		if err != nil {
			t.Errorf("decryptResponse failed for '%s': %v", msg, err)
			continue
		}
		if string(decrypted) != msg {
			t.Errorf("Roundtrip failed: expected '%s', got '%s'", msg, decrypted)
		}
	}
}

func TestDecryptResponse_NoKey(t *testing.T) {
	p := NewTCPProfile("", "", false)
	msg := []byte("plaintext")
	result, err := p.decryptResponse(msg)
	if err != nil {
		t.Errorf("decryptResponse without key should succeed: %v", err)
	}
	if string(result) != string(msg) {
		t.Error("Without key, decryptResponse should return original message")
	}
}

func TestDecryptResponse_TooShort(t *testing.T) {
	key := generateTestKey()
	p := NewTCPProfile("", key, false)
	_, err := p.decryptResponse([]byte("short"))
	if err == nil {
		t.Error("Expected error for too-short encrypted data")
	}
}

func TestDecryptResponse_InvalidHMAC(t *testing.T) {
	key := generateTestKey()
	p := NewTCPProfile("", key, false)

	// Create a fake message with correct structure but wrong HMAC
	uuid := "12345678-1234-1234-1234-123456789012"
	fakeIV := make([]byte, aes.BlockSize)
	rand.Read(fakeIV)
	fakeCiphertext := make([]byte, 32) // 2 blocks
	rand.Read(fakeCiphertext)
	fakeHMAC := make([]byte, 32)
	rand.Read(fakeHMAC)

	data := append([]byte(uuid), fakeIV...)
	data = append(data, fakeCiphertext...)
	data = append(data, fakeHMAC...)

	_, err := p.decryptResponse(data)
	if err == nil {
		t.Error("Expected HMAC verification error")
	}
}

// --- PKCS7 Padding ---

func TestPKCS7Pad(t *testing.T) {
	tests := []struct {
		input     []byte
		blockSize int
		padLen    int
	}{
		{[]byte("hello"), 16, 11},            // 5 bytes → 16 - 5 = 11 padding
		{[]byte("1234567890123456"), 16, 16}, // Exactly 16 → full block of padding
		{[]byte(""), 16, 16},                 // Empty → full block
		{[]byte("a"), 16, 15},                // 1 byte → 15 padding
	}

	for _, tt := range tests {
		padded := pkcs7Pad(tt.input, tt.blockSize)
		if len(padded)%tt.blockSize != 0 {
			t.Errorf("Padded length %d is not multiple of block size %d", len(padded), tt.blockSize)
		}
		lastByte := padded[len(padded)-1]
		if int(lastByte) != tt.padLen {
			t.Errorf("Expected padding byte %d, got %d", tt.padLen, lastByte)
		}
		// Verify all padding bytes are correct
		for i := len(padded) - tt.padLen; i < len(padded); i++ {
			if padded[i] != byte(tt.padLen) {
				t.Errorf("Padding byte at position %d should be %d, got %d", i, tt.padLen, padded[i])
			}
		}
	}
}

// --- Child Connection Management ---

func TestAddChildConnection(t *testing.T) {
	p := NewTCPProfile("", "", false)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p.AddChildConnection("test-uuid-1234", server)

	// Verify child is registered
	uuids := p.GetChildUUIDs()
	if len(uuids) != 1 {
		t.Errorf("Expected 1 child, got %d", len(uuids))
	}
	if uuids[0] != "test-uuid-1234" {
		t.Errorf("Expected UUID 'test-uuid-1234', got '%s'", uuids[0])
	}
}

func TestRemoveChildConnection(t *testing.T) {
	p := NewTCPProfile("", "", false)
	client, server := net.Pipe()
	defer client.Close()

	p.childMu.Lock()
	p.childConns["test-uuid"] = server
	p.childMu.Unlock()

	p.RemoveChildConnection("test-uuid")

	uuids := p.GetChildUUIDs()
	if len(uuids) != 0 {
		t.Errorf("Expected 0 children after removal, got %d", len(uuids))
	}
}

func TestRemoveChildConnection_Nonexistent(t *testing.T) {
	p := NewTCPProfile("", "", false)
	// Should not panic
	p.RemoveChildConnection("nonexistent-uuid")
}

func TestGetChildUUIDs_Empty(t *testing.T) {
	p := NewTCPProfile("", "", false)
	uuids := p.GetChildUUIDs()
	if len(uuids) != 0 {
		t.Errorf("Expected 0 children, got %d", len(uuids))
	}
}

func TestGetChildUUIDs_Multiple(t *testing.T) {
	p := NewTCPProfile("", "", false)

	for i := 0; i < 3; i++ {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		p.childMu.Lock()
		p.childConns[string(rune('a'+i))] = server
		p.childMu.Unlock()
	}

	uuids := p.GetChildUUIDs()
	if len(uuids) != 3 {
		t.Errorf("Expected 3 children, got %d", len(uuids))
	}
}

// --- DrainDelegatesAndEdges ---

func TestDrainDelegatesAndEdges_Empty(t *testing.T) {
	p := NewTCPProfile("", "", false)
	delegates, edges := p.DrainDelegatesAndEdges()
	if len(delegates) != 0 {
		t.Errorf("Expected 0 delegates, got %d", len(delegates))
	}
	if len(edges) != 0 {
		t.Errorf("Expected 0 edges, got %d", len(edges))
	}
}

func TestDrainDelegatesAndEdges_WithData(t *testing.T) {
	p := NewTCPProfile("", "", false)

	// Add delegate messages
	p.InboundDelegates <- structs.DelegateMessage{UUID: "child-1", Message: "msg1"}
	p.InboundDelegates <- structs.DelegateMessage{UUID: "child-2", Message: "msg2"}

	// Add edge messages
	p.EdgeMessages <- structs.P2PConnectionMessage{Source: "parent", Destination: "child-1", Action: "add"}

	delegates, edges := p.DrainDelegatesAndEdges()
	if len(delegates) != 2 {
		t.Errorf("Expected 2 delegates, got %d", len(delegates))
	}
	if len(edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(edges))
	}

	// Verify drain (should be empty now)
	delegates2, edges2 := p.DrainDelegatesAndEdges()
	if len(delegates2) != 0 || len(edges2) != 0 {
		t.Error("Channels should be empty after drain")
	}
}

// --- UUID Resolution ---

func TestResolveUUID_NoMapping(t *testing.T) {
	p := NewTCPProfile("", "", false)
	result := p.resolveUUID("original-uuid")
	if result != "original-uuid" {
		t.Errorf("Expected 'original-uuid', got '%s'", result)
	}
}

func TestResolveUUID_WithMapping(t *testing.T) {
	p := NewTCPProfile("", "", false)
	p.uuidMu.Lock()
	p.uuidMapping["temp-uuid"] = "real-mythic-uuid"
	p.uuidMu.Unlock()

	result := p.resolveUUID("temp-uuid")
	if result != "real-mythic-uuid" {
		t.Errorf("Expected 'real-mythic-uuid', got '%s'", result)
	}

	// Unmapped UUID should pass through
	result2 := p.resolveUUID("unknown-uuid")
	if result2 != "unknown-uuid" {
		t.Errorf("Expected 'unknown-uuid', got '%s'", result2)
	}
}

// --- getActiveUUID ---

func TestGetActiveUUID_WithCallbackUUID(t *testing.T) {
	p := NewTCPProfile("", "", false)
	p.CallbackUUID = "callback-uuid-123"
	agent := &structs.Agent{PayloadUUID: "payload-uuid-456"}

	result := p.getActiveUUID(agent)
	if result != "callback-uuid-123" {
		t.Errorf("Expected callback UUID, got '%s'", result)
	}
}

func TestGetActiveUUID_WithoutCallbackUUID(t *testing.T) {
	p := NewTCPProfile("", "", false)
	agent := &structs.Agent{PayloadUUID: "payload-uuid-456"}

	result := p.getActiveUUID(agent)
	if result != "payload-uuid-456" {
		t.Errorf("Expected payload UUID, got '%s'", result)
	}
}

// --- getString helper ---

func TestGetString(t *testing.T) {
	m := map[string]interface{}{
		"name":   "test",
		"number": 42,
		"nil":    nil,
	}

	if getString(m, "name") != "test" {
		t.Error("Expected 'test'")
	}
	if getString(m, "number") != "" {
		t.Error("Expected empty string for non-string value")
	}
	if getString(m, "missing") != "" {
		t.Error("Expected empty string for missing key")
	}
	if getString(m, "nil") != "" {
		t.Error("Expected empty string for nil value")
	}
}

// --- Route Delegates to Children ---

func TestRouteDelegatesToChildren(t *testing.T) {
	p := NewTCPProfile("", "", false)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p.childMu.Lock()
	p.childConns["child-uuid-1234"] = server
	p.childMu.Unlock()

	// Route a delegate to the child
	go func() {
		p.routeDelegatesToChildren([]structs.DelegateMessage{
			{UUID: "child-uuid-1234", Message: "hello child"},
		})
	}()

	// Read what was sent to the child connection
	header := make([]byte, 4)
	io.ReadFull(client, header)
	length := binary.BigEndian.Uint32(header)
	data := make([]byte, length)
	io.ReadFull(client, data)

	if string(data) != "hello child" {
		t.Errorf("Expected 'hello child', got '%s'", data)
	}
}

func TestRouteDelegatesToChildren_UUIDMapping(t *testing.T) {
	p := NewTCPProfile("", "", false)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Register child under temp UUID
	p.childMu.Lock()
	p.childConns["temp-uuid-1234"] = server
	p.childMu.Unlock()

	// Route with UUID correction (MythicUUID set)
	go func() {
		p.routeDelegatesToChildren([]structs.DelegateMessage{
			{UUID: "temp-uuid-1234", MythicUUID: "real-uuid-5678", Message: "remapped msg"},
		})
	}()

	// Give time for UUID mapping to happen
	time.Sleep(50 * time.Millisecond)

	// Read what was sent
	header := make([]byte, 4)
	io.ReadFull(client, header)
	length := binary.BigEndian.Uint32(header)
	data := make([]byte, length)
	io.ReadFull(client, data)

	if string(data) != "remapped msg" {
		t.Errorf("Expected 'remapped msg', got '%s'", data)
	}

	// Verify UUID was remapped
	p.childMu.RLock()
	_, hasNew := p.childConns["real-uuid-5678"]
	_, hasOld := p.childConns["temp-uuid-1234"]
	p.childMu.RUnlock()

	if !hasNew {
		t.Error("Expected child connection under new UUID")
	}
	if hasOld {
		t.Error("Old UUID should have been removed from child connections")
	}
}

func TestRouteDelegatesToChildren_NoConnection(t *testing.T) {
	p := NewTCPProfile("", "", false)
	// Should not panic when routing to nonexistent child
	p.routeDelegatesToChildren([]structs.DelegateMessage{
		{UUID: "nonexistent-uuid", Message: "lost message"},
	})
}

// --- Checkin Error Paths ---

func TestCheckin_EmptyBindAddress(t *testing.T) {
	p := NewTCPProfile("", "", false) // Empty bind address
	agent := &structs.Agent{PayloadUUID: "test-uuid"}
	err := p.Checkin(agent)
	if err == nil {
		t.Error("Expected error for empty bind address")
	}
}

// --- PostResponse/GetTasking with no parent connection ---

func TestGetTasking_NoParent(t *testing.T) {
	p := NewTCPProfile("", "", false)
	agent := &structs.Agent{PayloadUUID: "test-uuid"}
	_, _, err := p.GetTasking(agent, nil)
	if err == nil {
		t.Error("Expected error when no parent connection")
	}
}

func TestPostResponse_NoParent(t *testing.T) {
	p := NewTCPProfile("", "", false)
	agent := &structs.Agent{PayloadUUID: "test-uuid"}
	resp := structs.Response{TaskID: "task-1", UserOutput: "test"}
	_, err := p.PostResponse(resp, agent, nil)
	if err == nil {
		t.Error("Expected error when no parent connection")
	}
}

// --- RouteToChildren (public wrapper) ---

func TestRouteToChildren_Public(t *testing.T) {
	p := NewTCPProfile("", "", false)
	// Should not panic with empty delegates
	p.RouteToChildren(nil)
	p.RouteToChildren([]structs.DelegateMessage{})
}
