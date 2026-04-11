package commands

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/ssh"
)

// sshTunnelManager tracks active SSH tunnels for lifecycle management.
var sshTunnelManager = &tunnelManager{
	tunnels: make(map[string]*sshTunnel),
}

type tunnelManager struct {
	mu      sync.Mutex
	tunnels map[string]*sshTunnel
}

type sshTunnel struct {
	ID         string
	Type       string // "local", "remote", "dynamic"
	LocalAddr  string
	RemoteAddr string
	SSHTarget  string
	listener   net.Listener
	client     *ssh.Client
	cancel     context.CancelFunc
	conns      int
	started    time.Time
}

// sshTunnelLocal implements SSH local port forwarding (-L equivalent).
// Agent listens on localPort, forwards connections through SSH to remoteHost:remotePort.
func sshTunnelLocal(client *ssh.Client, args sshExecArgs, sshAddr string) structs.CommandResult {
	localAddr := fmt.Sprintf("%s:%d", args.BindAddress, args.LocalPort)
	remoteAddr := fmt.Sprintf("%s:%d", args.RemoteHost, args.RemotePort)

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return errorf("Error listening on %s: %v", localAddr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	tunnelID := fmt.Sprintf("ssh-local-%s-%d", args.Host, args.LocalPort)

	tunnel := &sshTunnel{
		ID:         tunnelID,
		Type:       "local",
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		SSHTarget:  sshAddr,
		listener:   listener,
		client:     client,
		cancel:     cancel,
		started:    time.Now(),
	}

	sshTunnelManager.mu.Lock()
	sshTunnelManager.tunnels[tunnelID] = tunnel
	sshTunnelManager.mu.Unlock()

	// Accept connections in background
	go func() {
		defer func() {
			listener.Close()
			client.Close()
			sshTunnelManager.mu.Lock()
			delete(sshTunnelManager.tunnels, tunnelID)
			sshTunnelManager.mu.Unlock()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Set accept deadline to allow periodic context check
			if tcpL, ok := listener.(*net.TCPListener); ok {
				_ = tcpL.SetDeadline(time.Now().Add(2 * time.Second))
			}

			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return // listener closed
			}

			tunnel.conns++

			// Open SSH channel to remote target
			go func(localConn net.Conn) {
				defer localConn.Close()

				remoteConn, err := client.Dial("tcp", remoteAddr)
				if err != nil {
					return
				}
				defer remoteConn.Close()

				// Bidirectional relay
				relaySSHTunnel(ctx, localConn, remoteConn)
			}(conn)
		}
	}()

	return successf("SSH local tunnel started: %s → [%s] → %s (ID: %s)\nUse jobkill to stop.",
		localAddr, sshAddr, remoteAddr, tunnelID)
}

// sshTunnelRemote implements SSH remote port forwarding (-R equivalent).
// Remote host listens on remotePort, forwards connections back through SSH to localHost:localPort.
func sshTunnelRemote(client *ssh.Client, args sshExecArgs, sshAddr string) structs.CommandResult {
	remoteAddr := fmt.Sprintf("0.0.0.0:%d", args.RemotePort)
	localTarget := net.JoinHostPort(args.LocalHost, fmt.Sprintf("%d", args.LocalPort))

	// Request remote listener via SSH
	listener, err := client.Listen("tcp", remoteAddr)
	if err != nil {
		return errorf("Error requesting remote listener on %s via %s: %v", remoteAddr, sshAddr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	tunnelID := fmt.Sprintf("ssh-remote-%s-%d", args.Host, args.RemotePort)

	tunnel := &sshTunnel{
		ID:         tunnelID,
		Type:       "remote",
		LocalAddr:  localTarget,
		RemoteAddr: remoteAddr,
		SSHTarget:  sshAddr,
		listener:   listener,
		client:     client,
		cancel:     cancel,
		started:    time.Now(),
	}

	sshTunnelManager.mu.Lock()
	sshTunnelManager.tunnels[tunnelID] = tunnel
	sshTunnelManager.mu.Unlock()

	go func() {
		defer func() {
			listener.Close()
			client.Close()
			sshTunnelManager.mu.Lock()
			delete(sshTunnelManager.tunnels, tunnelID)
			sshTunnelManager.mu.Unlock()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					return // listener closed
				}
			}

			tunnel.conns++

			// Connect to local target
			go func(remoteConn net.Conn) {
				defer remoteConn.Close()

				localConn, err := net.DialTimeout("tcp", localTarget, 10*time.Second)
				if err != nil {
					return
				}
				defer localConn.Close()

				relaySSHTunnel(ctx, remoteConn, localConn)
			}(conn)
		}
	}()

	return successf("SSH remote tunnel started: %s:[%s] → agent → %s (ID: %s)\nUse jobkill to stop.",
		sshAddr, remoteAddr, localTarget, tunnelID)
}

// sshTunnelDynamic implements SSH dynamic port forwarding (-D equivalent).
// Agent listens as a SOCKS5 proxy, routing connections through SSH.
func sshTunnelDynamic(client *ssh.Client, args sshExecArgs, sshAddr string) structs.CommandResult {
	localAddr := fmt.Sprintf("%s:%d", args.BindAddress, args.LocalPort)

	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return errorf("Error listening on %s: %v", localAddr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	tunnelID := fmt.Sprintf("ssh-dynamic-%s-%d", args.Host, args.LocalPort)

	tunnel := &sshTunnel{
		ID:         tunnelID,
		Type:       "dynamic",
		LocalAddr:  localAddr,
		RemoteAddr: "SOCKS5",
		SSHTarget:  sshAddr,
		listener:   listener,
		client:     client,
		cancel:     cancel,
		started:    time.Now(),
	}

	sshTunnelManager.mu.Lock()
	sshTunnelManager.tunnels[tunnelID] = tunnel
	sshTunnelManager.mu.Unlock()

	go func() {
		defer func() {
			listener.Close()
			client.Close()
			sshTunnelManager.mu.Lock()
			delete(sshTunnelManager.tunnels, tunnelID)
			sshTunnelManager.mu.Unlock()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if tcpL, ok := listener.(*net.TCPListener); ok {
				_ = tcpL.SetDeadline(time.Now().Add(2 * time.Second))
			}

			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			tunnel.conns++

			go handleSOCKS5ViaSSH(ctx, conn, client)
		}
	}()

	return successf("SSH dynamic SOCKS5 proxy started: %s → [%s] (ID: %s)\nUse jobkill to stop.",
		localAddr, sshAddr, tunnelID)
}

// handleSOCKS5ViaSSH handles a SOCKS5 connection by routing through SSH.
func handleSOCKS5ViaSSH(ctx context.Context, conn net.Conn, client *ssh.Client) {
	defer conn.Close()

	// SOCKS5 handshake
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	// Accept no-auth
	_, _ = conn.Write([]byte{0x05, 0x00})

	// Read request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	if buf[1] != 0x01 { // Only CONNECT supported
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}

	var targetAddr string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
			uint16(buf[8])<<8|uint16(buf[9]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		domain := string(buf[5 : 5+domainLen])
		port := uint16(buf[5+domainLen])<<8 | uint16(buf[5+domainLen+1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		ip := net.IP(buf[4:20])
		port := uint16(buf[20])<<8 | uint16(buf[21])
		targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // address type not supported
		return
	}

	// Connect through SSH
	remoteConn, err := client.Dial("tcp", targetAddr)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer remoteConn.Close()

	// Send success response
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // success, bound to 0.0.0.0:0

	relaySSHTunnel(ctx, conn, remoteConn)
}

// sshTunnelList returns a list of active SSH tunnels.
func sshTunnelList() structs.CommandResult {
	sshTunnelManager.mu.Lock()
	defer sshTunnelManager.mu.Unlock()

	if len(sshTunnelManager.tunnels) == 0 {
		return successResult("No active SSH tunnels")
	}

	var lines []string
	for _, t := range sshTunnelManager.tunnels {
		uptime := time.Since(t.started).Round(time.Second)
		lines = append(lines, fmt.Sprintf("  %s [%s] %s → %s via %s (%d conns, up %s)",
			t.ID, t.Type, t.LocalAddr, t.RemoteAddr, t.SSHTarget, t.conns, uptime))
	}

	return successf("Active SSH tunnels (%d):\n%s", len(sshTunnelManager.tunnels),
		joinLines(lines))
}

// sshTunnelStop stops a specific SSH tunnel by ID.
func sshTunnelStop(tunnelID string) structs.CommandResult {
	sshTunnelManager.mu.Lock()
	tunnel, ok := sshTunnelManager.tunnels[tunnelID]
	sshTunnelManager.mu.Unlock()

	if !ok {
		// Try prefix match
		sshTunnelManager.mu.Lock()
		for id, t := range sshTunnelManager.tunnels {
			if len(tunnelID) > 3 && len(id) > len(tunnelID) && id[:len(tunnelID)] == tunnelID {
				tunnel = t
				ok = true
				break
			}
		}
		sshTunnelManager.mu.Unlock()
	}

	if !ok {
		return errorf("Tunnel not found: %s", tunnelID)
	}

	tunnel.cancel()
	tunnel.listener.Close()
	tunnel.client.Close()

	return successf("Stopped tunnel: %s [%s] %s → %s (%d total connections)",
		tunnel.ID, tunnel.Type, tunnel.LocalAddr, tunnel.RemoteAddr, tunnel.conns)
}

// relaySSHTunnel relays data bidirectionally between two connections.
func relaySSHTunnel(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)

	relay := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = src.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, err := src.Read(buf)
			if n > 0 {
				if _, wErr := dst.Write(buf[:n]); wErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	go relay(a, b)
	go relay(b, a)

	// Wait for either direction to finish or context cancel
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// joinLines joins string slices with newlines.
func joinLines(lines []string) string {
	result := ""
	for i, l := range lines {
		if i > 0 {
			result += "\n"
		}
		result += l
	}
	return result
}
