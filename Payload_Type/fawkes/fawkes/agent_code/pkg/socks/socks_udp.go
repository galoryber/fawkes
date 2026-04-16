package socks

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

const (
	udpAssociateCommand = 0x03

	// UDP relay timeouts
	udpReadTimeout  = 30 * time.Second
	udpWriteTimeout = 10 * time.Second
	udpIdleTimeout  = 2 * time.Minute // shorter than TCP since UDP sessions are brief
	udpMaxPacket    = 65535            // max UDP datagram size
)

// udpRelay represents a single UDP ASSOCIATE session.
// It maintains a local UDP socket for sending/receiving datagrams
// and maps client-side serverIds to target addresses.
type udpRelay struct {
	serverId uint32
	conn     *net.UDPConn
	manager  *Manager
	done     chan struct{}
	mu       sync.Mutex
	targets  map[string]*net.UDPAddr // target address -> resolved addr cache
}

// handleUDPAssociate processes a SOCKS5 UDP ASSOCIATE request (RFC 1928 §7).
// The client indicates which address/port it will send UDP from. We create
// a local UDP socket for relaying and reply with success.
func (m *Manager) handleUDPAssociate(serverId uint32, data []byte) {
	// Parse the client's indicated source address (DST.ADDR + DST.PORT)
	// Per RFC 1928: if DST.ADDR is 0.0.0.0 and DST.PORT is 0, the client
	// expects the relay to accept from any source.
	// We don't restrict by source since traffic comes through Mythic.

	// Create local UDP socket for outbound relay
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		log.Printf("udp resolve error sid=%d: %v", serverId, err)
		m.sendReply(serverId, replyConnectionRefused)
		m.queueExit(serverId)
		return
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("udp listen error sid=%d: %v", serverId, err)
		m.sendReply(serverId, replyConnectionRefused)
		m.queueExit(serverId)
		return
	}

	relay := &udpRelay{
		serverId: serverId,
		conn:     conn,
		manager:  m,
		done:     make(chan struct{}),
		targets:  make(map[string]*net.UDPAddr),
	}

	// Store the relay
	m.mu.Lock()
	if m.udpRelays == nil {
		m.udpRelays = make(map[uint32]*udpRelay)
	}
	m.udpRelays[serverId] = relay
	m.mu.Unlock()

	// Track stats
	m.Stats.RecordConnect(serverId, "UDP-ASSOCIATE")

	// Send success reply with bind address 0.0.0.0:0
	// In the Mythic architecture, the client sends UDP data through the
	// same SocksMsg channel, so the bind address is informational.
	m.sendReply(serverId, replySuccess)

	// Start UDP response reader goroutine
	go relay.readResponses()
}

// forwardUDP parses a SOCKS5 UDP request header and relays the datagram.
// RFC 1928 §7 UDP request format:
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
func (m *Manager) forwardUDP(serverId uint32, b64Data string) {
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil || len(data) < 4 {
		log.Printf("udp decode error sid=%d", serverId)
		return
	}

	m.mu.Lock()
	relay, exists := m.udpRelays[serverId]
	m.mu.Unlock()
	if !exists {
		log.Printf("udp relay not found sid=%d", serverId)
		return
	}

	// Parse SOCKS5 UDP header
	// RSV (2 bytes) + FRAG (1 byte) + ATYP (1 byte)
	frag := data[2]
	if frag != 0 {
		// Fragmentation not supported — drop silently per RFC 1928
		return
	}

	addrType := data[3]
	var host string
	var portOffset int

	switch addrType {
	case addrTypeIPv4:
		if len(data) < 10 {
			return
		}
		host = net.IP(data[4:8]).String()
		portOffset = 8
	case addrTypeDomain:
		if len(data) < 5 {
			return
		}
		domainLen := int(data[4])
		if len(data) < 5+domainLen+2 {
			return
		}
		host = string(data[5 : 5+domainLen])
		portOffset = 5 + domainLen
	case addrTypeIPv6:
		if len(data) < 22 {
			return
		}
		host = net.IP(data[4:20]).String()
		portOffset = 20
	default:
		log.Printf("udp unsupported addr=%d sid=%d", addrType, serverId)
		return
	}

	if len(data) < portOffset+2 {
		return
	}
	port := binary.BigEndian.Uint16(data[portOffset : portOffset+2])
	payload := data[portOffset+2:]

	if len(payload) == 0 {
		return
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// Resolve and cache target address
	relay.mu.Lock()
	udpTarget, cached := relay.targets[target]
	relay.mu.Unlock()

	if !cached {
		udpTarget, err = net.ResolveUDPAddr("udp", target)
		if err != nil {
			log.Printf("udp resolve %s error sid=%d: %v", target, serverId, err)
			return
		}
		relay.mu.Lock()
		relay.targets[target] = udpTarget
		relay.mu.Unlock()
	}

	// Send the payload to the target
	_ = relay.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
	n, err := relay.conn.WriteToUDP(payload, udpTarget)
	if err != nil {
		log.Printf("udp write error sid=%d target=%s: %v", serverId, target, err)
		return
	}
	m.Stats.RecordSend(serverId, n)
}

// readResponses reads UDP responses from target servers and queues them
// as outbound SocksMsg with SOCKS5 UDP reply headers.
func (r *udpRelay) readResponses() {
	buf := make([]byte, udpMaxPacket)
	for {
		select {
		case <-r.done:
			return
		default:
		}

		_ = r.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, remoteAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if we were closed
				select {
				case <-r.done:
					return
				default:
					// Idle timeout — close the relay
					log.Printf("udp idle timeout sid=%d", r.serverId)
					r.manager.closeUDPRelay(r.serverId, "timeout")
					return
				}
			}
			// Real error
			log.Printf("udp read error sid=%d: %v", r.serverId, err)
			r.manager.closeUDPRelay(r.serverId, "error")
			return
		}

		if n == 0 {
			continue
		}

		r.manager.Stats.RecordRecv(r.serverId, n)

		// Build SOCKS5 UDP reply header
		// RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT + DATA
		ip := remoteAddr.IP
		port := uint16(remoteAddr.Port)

		var header []byte
		if ip4 := ip.To4(); ip4 != nil {
			header = make([]byte, 10)
			header[3] = addrTypeIPv4
			copy(header[4:8], ip4)
			binary.BigEndian.PutUint16(header[8:10], port)
		} else {
			header = make([]byte, 22)
			header[3] = addrTypeIPv6
			copy(header[4:20], ip.To16())
			binary.BigEndian.PutUint16(header[20:22], port)
		}

		reply := append(header, buf[:n]...)
		encoded := base64.StdEncoding.EncodeToString(reply)

		r.manager.mu.Lock()
		r.manager.outbound = append(r.manager.outbound, structs.SocksMsg{
			ServerId: r.serverId,
			Data:     encoded,
			Exit:     false,
		})
		r.manager.mu.Unlock()
	}
}

// closeUDPRelay closes a UDP relay and cleans up resources.
func (m *Manager) closeUDPRelay(serverId uint32, reason string) {
	m.mu.Lock()
	relay, exists := m.udpRelays[serverId]
	if exists {
		delete(m.udpRelays, serverId)
	}
	m.mu.Unlock()

	if exists {
		close(relay.done)
		relay.conn.Close()
		m.Stats.RecordClose(serverId, reason)

		// Send exit message
		m.mu.Lock()
		m.outbound = append(m.outbound, structs.SocksMsg{
			ServerId: serverId,
			Data:     "",
			Exit:     true,
		})
		m.mu.Unlock()
	}
}
