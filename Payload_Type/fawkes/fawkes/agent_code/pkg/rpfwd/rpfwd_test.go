package rpfwd

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestConstants(t *testing.T) {
	if readBufSize != 32*1024 {
		t.Errorf("readBufSize = %d, want 32768", readBufSize)
	}
	if idleReadTimeout != 5*time.Minute {
		t.Errorf("idleReadTimeout = %v, want 5m", idleReadTimeout)
	}
}

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
		return
	}
	if m.listeners == nil {
		t.Error("listeners map not initialized")
	}
	if m.connections == nil {
		t.Error("connections map not initialized")
	}
	if m.IdleReadTimeout != idleReadTimeout {
		t.Errorf("IdleReadTimeout = %v, want %v", m.IdleReadTimeout, idleReadTimeout)
	}
}

func TestDrainOutboundEmpty(t *testing.T) {
	m := NewManager()
	msgs := m.DrainOutbound()
	if msgs != nil {
		t.Errorf("expected nil, got %d messages", len(msgs))
	}
}

func TestDrainOutboundClearsQueue(t *testing.T) {
	m := NewManager()
	m.mu.Lock()
	m.outbound = append(m.outbound, structs.SocksMsg{ServerId: 1, Data: "test"})
	m.outbound = append(m.outbound, structs.SocksMsg{ServerId: 2, Data: "test2"})
	m.mu.Unlock()

	msgs := m.DrainOutbound()
	if len(msgs) != 2 {
		t.Errorf("expected 2 messages, got %d", len(msgs))
	}

	// Second drain should be empty
	msgs2 := m.DrainOutbound()
	if msgs2 != nil {
		t.Errorf("expected nil after drain, got %d messages", len(msgs2))
	}
}

func TestStartAndStop(t *testing.T) {
	m := NewManager()

	// Start on a random port
	port := findFreePort(t)
	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Verify listener exists
	m.mu.Lock()
	_, ok := m.listeners[uint32(port)]
	m.mu.Unlock()
	if !ok {
		t.Error("listener not in map after Start")
	}

	// Stop
	err = m.Stop(uint32(port))
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	m.mu.Lock()
	_, ok = m.listeners[uint32(port)]
	m.mu.Unlock()
	if ok {
		t.Error("listener still in map after Stop")
	}
}

func TestStopNonExistent(t *testing.T) {
	m := NewManager()
	err := m.Stop(99999)
	if err == nil {
		t.Error("expected error stopping non-existent port")
	}
}

func TestStartDuplicatePort(t *testing.T) {
	m := NewManager()
	port := findFreePort(t)

	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	defer m.Stop(uint32(port))

	// Starting on same port should close old listener and create new one
	err = m.Start(uint32(port))
	if err != nil {
		t.Fatalf("second Start failed: %v", err)
	}
}

func TestConnectionAccepted(t *testing.T) {
	m := NewManager()
	port := findFreePort(t)

	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop(uint32(port))

	// Connect to the listener
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Send some data
	_, err = conn.Write([]byte("hello rpfwd"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Wait for data to be queued
	time.Sleep(100 * time.Millisecond)

	// Drain outbound — should have the data we sent
	msgs := m.DrainOutbound()
	if len(msgs) == 0 {
		t.Fatal("expected outbound messages after write")
	}

	found := false
	for _, msg := range msgs {
		if msg.Data != "" && !msg.Exit {
			data, err := base64.StdEncoding.DecodeString(msg.Data)
			if err != nil {
				continue
			}
			if string(data) == "hello rpfwd" {
				found = true
				if msg.Port != uint32(port) {
					t.Errorf("expected port %d, got %d", port, msg.Port)
				}
			}
		}
	}
	if !found {
		t.Error("didn't find expected data in outbound messages")
	}
}

func TestHandleMessagesWriteToConnection(t *testing.T) {
	m := NewManager()
	port := findFreePort(t)

	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop(uint32(port))

	// Connect to the listener
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Wait for connection to be registered
	time.Sleep(100 * time.Millisecond)

	// Find the server_id from outbound messages (or from connections map)
	m.mu.Lock()
	var serverID uint32
	for id := range m.connections {
		serverID = id
		break
	}
	m.mu.Unlock()

	if serverID == 0 {
		// The connection might have sent data already — drain to find it
		m.DrainOutbound()
		m.mu.Lock()
		for id := range m.connections {
			serverID = id
			break
		}
		m.mu.Unlock()
	}

	if serverID == 0 {
		t.Fatal("no connection registered")
	}

	// Send data from "Mythic" to the connection
	testData := "data from mythic"
	encoded := base64.StdEncoding.EncodeToString([]byte(testData))
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: serverID, Data: encoded, Exit: false, Port: uint32(port)},
	})

	// Read data from our connection
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf[:n]) != testData {
		t.Errorf("expected %q, got %q", testData, string(buf[:n]))
	}
}

func TestHandleMessagesExit(t *testing.T) {
	m := NewManager()
	port := findFreePort(t)

	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop(uint32(port))

	// Connect
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	time.Sleep(100 * time.Millisecond)

	// Find server_id
	m.mu.Lock()
	var serverID uint32
	for id := range m.connections {
		serverID = id
		break
	}
	m.mu.Unlock()

	if serverID == 0 {
		t.Fatal("no connection registered")
	}

	// Send exit message
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: serverID, Exit: true, Port: uint32(port)},
	})

	time.Sleep(100 * time.Millisecond)

	// Connection should be removed
	m.mu.Lock()
	_, exists := m.connections[serverID]
	m.mu.Unlock()

	if exists {
		t.Error("connection still exists after exit message")
	}
}

func TestHandleMessagesUnknownConnection(t *testing.T) {
	m := NewManager()

	// Sending to unknown connection should queue an exit
	m.HandleMessages([]structs.SocksMsg{
		{ServerId: 12345, Data: "test", Exit: false, Port: 8080},
	})

	msgs := m.DrainOutbound()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 exit message, got %d", len(msgs))
	}
	if !msgs[0].Exit {
		t.Error("expected exit message")
	}
	if msgs[0].ServerId != 12345 {
		t.Errorf("expected server_id 12345, got %d", msgs[0].ServerId)
	}
}

func TestConnectionClosed(t *testing.T) {
	m := NewManager()
	port := findFreePort(t)

	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop(uint32(port))

	// Connect and then close
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Drain should contain an exit message
	msgs := m.DrainOutbound()
	hasExit := false
	for _, msg := range msgs {
		if msg.Exit {
			hasExit = true
			break
		}
	}
	if !hasExit {
		t.Error("expected exit message after connection close")
	}
}

func TestReadFromConnection_IdleTimeout(t *testing.T) {
	m := NewManager()
	m.IdleReadTimeout = 200 * time.Millisecond

	port := findFreePort(t)
	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop(uint32(port))

	// Connect but send no data — should trigger idle timeout
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Wait for connection registration + idle timeout + cleanup
	time.Sleep(500 * time.Millisecond)

	// Should have an exit message from the idle timeout
	msgs := m.DrainOutbound()
	hasExit := false
	for _, msg := range msgs {
		if msg.Exit {
			hasExit = true
			break
		}
	}
	if !hasExit {
		t.Error("expected exit message from idle timeout")
	}

	// Connection should be removed from tracking
	m.mu.Lock()
	connCount := len(m.connections)
	m.mu.Unlock()
	if connCount != 0 {
		t.Errorf("expected 0 connections after idle timeout, got %d", connCount)
	}
}

func TestReadFromConnection_ActiveConnectionNotTimedOut(t *testing.T) {
	m := NewManager()
	m.IdleReadTimeout = 300 * time.Millisecond

	port := findFreePort(t)
	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop(uint32(port))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Send data within the timeout window to keep connection alive
	time.Sleep(100 * time.Millisecond)
	_, err = conn.Write([]byte("keepalive1"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Connection should still be active
	m.mu.Lock()
	connCount := len(m.connections)
	m.mu.Unlock()
	if connCount != 1 {
		t.Errorf("expected 1 active connection, got %d", connCount)
	}

	// Should have data messages (not exit)
	msgs := m.DrainOutbound()
	hasData := false
	for _, msg := range msgs {
		if !msg.Exit && msg.Data != "" {
			hasData = true
			break
		}
	}
	if !hasData {
		t.Error("expected data messages from active connection")
	}
}

func TestReadFromConnection_ExternalCloseBeforeTimeout(t *testing.T) {
	m := NewManager()
	m.IdleReadTimeout = 300 * time.Millisecond

	port := findFreePort(t)
	err := m.Start(uint32(port))
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop(uint32(port))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Find the server ID
	m.mu.Lock()
	var serverID uint32
	for id := range m.connections {
		serverID = id
		break
	}
	m.mu.Unlock()

	// Externally close the connection via the manager (simulates Mythic exit)
	m.closeConnection(serverID)

	// Wait for the read goroutine to notice
	time.Sleep(200 * time.Millisecond)
	conn.Close()

	// Connection should be gone
	m.mu.Lock()
	_, exists := m.connections[serverID]
	m.mu.Unlock()
	if exists {
		t.Error("connection should be removed after external close")
	}
}

// --- Forward Port Forward Tests ---

func TestStartForwardAndStop(t *testing.T) {
	m := NewManager()

	// Start a target echo server
	targetPort := findFreePort(t)
	targetListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("failed to start target: %v", err)
	}
	defer targetListener.Close()
	go echoServer(targetListener)

	// Start forward
	listenPort := findFreePort(t)
	err = m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("StartForward failed: %v", err)
	}

	// Verify relay exists
	m.mu.Lock()
	_, ok := m.forwardRelays[uint32(listenPort)]
	m.mu.Unlock()
	if !ok {
		t.Error("forward relay not in map after StartForward")
	}

	// Stop
	err = m.Stop(uint32(listenPort))
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	m.mu.Lock()
	_, ok = m.forwardRelays[uint32(listenPort)]
	m.mu.Unlock()
	if ok {
		t.Error("forward relay still in map after Stop")
	}
}

func TestForwardDataRelay(t *testing.T) {
	m := NewManager()
	m.IdleReadTimeout = 5 * time.Second

	// Start a target echo server
	targetPort := findFreePort(t)
	targetListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("failed to start target: %v", err)
	}
	defer targetListener.Close()
	go echoServer(targetListener)

	// Start forward relay
	listenPort := findFreePort(t)
	err = m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("StartForward failed: %v", err)
	}
	defer m.Stop(uint32(listenPort))

	// Connect through the relay
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to relay: %v", err)
	}
	defer conn.Close()

	// Send data — should be echoed back through the relay
	testData := "hello forward relay"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf[:n]) != testData {
		t.Errorf("expected %q, got %q", testData, string(buf[:n]))
	}
}

func TestForwardNoRpfwdMessages(t *testing.T) {
	m := NewManager()
	m.IdleReadTimeout = 5 * time.Second

	// Start a target echo server
	targetPort := findFreePort(t)
	targetListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("failed to start target: %v", err)
	}
	defer targetListener.Close()
	go echoServer(targetListener)

	// Start forward relay
	listenPort := findFreePort(t)
	err = m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("StartForward failed: %v", err)
	}
	defer m.Stop(uint32(listenPort))

	// Connect and exchange data
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	_, err = conn.Write([]byte("test"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Forward relay should NOT generate rpfwd outbound messages
	msgs := m.DrainOutbound()
	if msgs != nil {
		t.Errorf("forward relay should not generate rpfwd messages, got %d", len(msgs))
	}
}

func TestForwardTargetUnreachable(t *testing.T) {
	m := NewManager()

	// Start forward to a port nothing is listening on
	listenPort := findFreePort(t)
	deadPort := findFreePort(t)
	err := m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", deadPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("StartForward failed: %v", err)
	}
	defer m.Stop(uint32(listenPort))

	// Connect — the relay should accept but fail to connect to target
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// The connection should be closed by the relay since target is unreachable
	time.Sleep(200 * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected error reading from closed relay connection")
	}
}

func TestForwardBindAddress(t *testing.T) {
	m := NewManager()

	targetPort := findFreePort(t)
	targetListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("failed to start target: %v", err)
	}
	defer targetListener.Close()
	go echoServer(targetListener)

	// Start forward with 127.0.0.1 bind
	listenPort := findFreePort(t)
	err = m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("StartForward with 127.0.0.1 failed: %v", err)
	}

	m.mu.Lock()
	relay := m.forwardRelays[uint32(listenPort)]
	m.mu.Unlock()
	if relay.bindAddr != "127.0.0.1" {
		t.Errorf("expected bindAddr 127.0.0.1, got %s", relay.bindAddr)
	}

	m.Stop(uint32(listenPort))
}

func TestForwardDefaultBindAddress(t *testing.T) {
	m := NewManager()

	targetPort := findFreePort(t)
	listenPort := findFreePort(t)

	err := m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "")
	if err != nil {
		t.Fatalf("StartForward with empty bind failed: %v", err)
	}
	defer m.Stop(uint32(listenPort))

	m.mu.Lock()
	relay := m.forwardRelays[uint32(listenPort)]
	m.mu.Unlock()
	if relay.bindAddr != "0.0.0.0" {
		t.Errorf("expected default bindAddr 0.0.0.0, got %s", relay.bindAddr)
	}
}

func TestForwardDuplicatePort(t *testing.T) {
	m := NewManager()

	targetPort := findFreePort(t)
	targetListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("failed to start target: %v", err)
	}
	defer targetListener.Close()

	listenPort := findFreePort(t)

	// Start first forward
	err = m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("first StartForward failed: %v", err)
	}

	// Start second forward on same port — should replace the first
	err = m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("second StartForward failed: %v", err)
	}

	m.Stop(uint32(listenPort))
}

func TestForwardIdleTimeout(t *testing.T) {
	m := NewManager()
	m.IdleReadTimeout = 200 * time.Millisecond

	targetPort := findFreePort(t)
	targetListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("failed to start target: %v", err)
	}
	defer targetListener.Close()
	go echoServer(targetListener)

	listenPort := findFreePort(t)
	err = m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("StartForward failed: %v", err)
	}
	defer m.Stop(uint32(listenPort))

	// Connect but don't send data
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Wait for idle timeout
	time.Sleep(500 * time.Millisecond)

	// Connection should be cleaned up
	m.mu.Lock()
	connCount := len(m.connections)
	m.mu.Unlock()
	if connCount != 0 {
		t.Errorf("expected 0 connections after idle timeout, got %d", connCount)
	}
}

func TestCloseIncludesForwardRelays(t *testing.T) {
	m := NewManager()

	targetPort := findFreePort(t)
	listenPort := findFreePort(t)

	err := m.StartForward(uint32(listenPort), fmt.Sprintf("127.0.0.1:%d", targetPort), "127.0.0.1")
	if err != nil {
		t.Fatalf("StartForward failed: %v", err)
	}

	m.Close()

	m.mu.Lock()
	fwdCount := len(m.forwardRelays)
	m.mu.Unlock()
	if fwdCount != 0 {
		t.Errorf("expected 0 forward relays after Close, got %d", fwdCount)
	}
}

func TestNewManagerHasForwardRelays(t *testing.T) {
	m := NewManager()
	if m.forwardRelays == nil {
		t.Error("forwardRelays map not initialized")
	}
}

// echoServer accepts connections and echoes data back
func echoServer(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		}(conn)
	}
}

// findFreePort finds a free TCP port for testing
func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
